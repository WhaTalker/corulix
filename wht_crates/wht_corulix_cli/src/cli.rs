// SPDX-FileCopyrightText: 2026 WhaTalker Inc.
// SPDX-License-Identifier: AGPL-3.0-only

//! The canonical `corulix` command model.
//!
//! This is the **sole** authority for the public CLI grammar (Architecture
//! Rule I): every command, flag, and mutual-exclusion relationship is
//! defined here as real `clap` derive types, and nothing else in this
//! binary hand-parses the raw process argument vector or maintains a
//! second, parallel command tree. `--help`/`-h`/`--version`/the built-in
//! `help` subcommand are all rendered directly from this model by `clap`
//! itself -- they cannot drift from what the parser actually accepts,
//! because they use the same model.

use crate::help;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "corulix",
    version = env!("CARGO_PKG_VERSION"),
    about = "WhaTalker Corulix -- enterprise code intelligence and MCP server",
    long_about = help::TOP_LEVEL_LONG_ABOUT
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

/// A single-root or multi-root workspace selector, shared by every command
/// that needs one. `--workspace` and `--workspace-file` are mutually
/// exclusive at the parser level (`conflicts_with`) -- this is a real
/// `clap` constraint, not documentation-only.
#[derive(clap::Args, Debug, Clone)]
pub struct WorkspaceSelection {
    /// Bind a single-root workspace at this directory.
    #[arg(long, value_name = "DIRECTORY", conflicts_with = "workspace_file")]
    pub workspace: Option<PathBuf>,

    /// Bind a multi-root workspace from this VS Code `.code-workspace` file.
    #[arg(long, value_name = "FILE")]
    pub workspace_file: Option<PathBuf>,
}

/// An optional member-root selector for operations that target one
/// specific root inside a multi-root workspace.
#[derive(clap::Args, Debug, Clone)]
pub struct RootSelector {
    /// Select one member root (by display name or opaque root ID) inside a
    /// multi-root workspace. Required whenever the target operation would
    /// otherwise be ambiguous across multiple roots; not needed for a
    /// single-root workspace.
    #[arg(long, value_name = "ROOT")]
    pub workspace_root: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Inspect local toolchain/runtime availability
    #[command(long_about = help::TOOLCHAIN_LONG_ABOUT)]
    Toolchain {
        #[command(subcommand)]
        command: ToolchainCommand,
    },
    /// Inspect supported languages and structural (syntax) capabilities
    #[command(long_about = help::LANGUAGES_LONG_ABOUT)]
    Languages {
        #[command(subcommand)]
        command: LanguagesCommand,
    },
    /// Detect and inspect the active workspace context
    #[command(long_about = help::WORKSPACE_LONG_ABOUT)]
    Workspace {
        #[command(subcommand)]
        command: WorkspaceCommand,
    },
    /// Parse a source file within the active workspace
    #[command(long_about = help::PARSE_LONG_ABOUT)]
    Parse {
        /// Workspace-relative path to the file to parse
        file: String,
        #[command(flatten)]
        workspace: WorkspaceSelection,
        #[command(flatten)]
        root: RootSelector,
    },
    /// Run Corulix MCP transports
    #[command(long_about = help::MCP_LONG_ABOUT)]
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Bootstrap or change this host's persisted managed-toolchain install profile
    #[command(long_about = help::SETUP_LONG_ABOUT)]
    Setup {
        /// Install profile to persist: `full` (eager, acquire every
        /// applicable component now) or `on-demand` (persist nothing eager;
        /// acquire lazily on first real use). Omit to leave an existing
        /// explicit choice untouched, or bootstrap to `full` if none has
        /// ever been persisted. Conflicts with `--only`/`--exclude`.
        #[arg(long, value_enum, value_name = "PROFILE")]
        profile: Option<SetupProfileArg>,
        /// Select only these install groups (repeatable, or comma-separated),
        /// e.g. `--only rust --only python` or `--only rust,python`.
        /// Persists the expanded, dependency-closed component set as a
        /// Selective profile. Conflicts with `--profile on-demand`.
        #[arg(long, value_name = "GROUP", value_delimiter = ',')]
        only: Vec<String>,
        /// Exclude these install groups from the full (or `--only`-limited)
        /// set. Conflicts with `--profile on-demand`.
        #[arg(long, value_name = "GROUP", value_delimiter = ',')]
        exclude: Vec<String>,
    },
}

/// `corulix setup --profile <PROFILE>`'s recognized values. Kebab-cased by
/// `clap`'s own `ValueEnum` derive default (`OnDemand` -> `"on-demand"`) --
/// this is the literal CLI string, not an independent rename declared here.
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum SetupProfileArg {
    Full,
    OnDemand,
}

#[derive(Subcommand, Debug)]
pub enum ToolchainCommand {
    /// Print current toolchain/runtime diagnostics
    #[command(long_about = help::TOOLCHAIN_STATUS_LONG_ABOUT)]
    Status {
        #[command(flatten)]
        workspace: WorkspaceSelection,
    },
}

#[derive(Subcommand, Debug)]
pub enum LanguagesCommand {
    /// List every currently supported language and its pinned grammar
    #[command(long_about = help::LANGUAGES_LIST_LONG_ABOUT)]
    List {
        #[command(flatten)]
        workspace: WorkspaceSelection,
    },
}

#[derive(Subcommand, Debug)]
pub enum WorkspaceCommand {
    /// Show workspace resolution diagnostics without opening the engine
    #[command(long_about = help::WORKSPACE_DETECT_LONG_ABOUT)]
    Detect {
        #[command(flatten)]
        workspace: WorkspaceSelection,
    },
    /// Inspect the resolved workspace (redacted: never the raw absolute root)
    #[command(long_about = help::WORKSPACE_INSPECT_LONG_ABOUT)]
    Inspect {
        #[command(flatten)]
        workspace: WorkspaceSelection,
        #[command(flatten)]
        root: RootSelector,
    },
}

#[derive(Subcommand, Debug)]
pub enum McpCommand {
    /// Serve the MCP protocol over stdio
    #[command(long_about = help::MCP_STDIO_LONG_ABOUT)]
    Stdio {
        #[command(flatten)]
        workspace: WorkspaceSelection,
        /// Absolute path to a HOST_ONLY host-config TOML file (F1 fix).
        /// Host/operator-only: never readable from or writable by any MCP
        /// request, workspace file, or repository hint. Omit for today's
        /// unchanged default (untrusted, no configured providers).
        #[arg(long, value_name = "ABSOLUTE_FILE")]
        host_config: Option<PathBuf>,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use clap::error::ErrorKind;

    fn assert_help_or_version(args: &[&str], expected: ErrorKind) {
        let result = Cli::try_parse_from(args);
        let is_expected_kind = matches!(&result, Err(error) if error.kind() == expected);
        assert!(
            is_expected_kind,
            "expected {expected:?} for {args:?}, got {result:?}"
        );
    }

    #[test]
    fn top_level_help_and_version_exit_zero_equivalent() {
        assert_help_or_version(&["corulix", "--help"], ErrorKind::DisplayHelp);
        assert_help_or_version(&["corulix", "-h"], ErrorKind::DisplayHelp);
        assert_help_or_version(&["corulix", "--version"], ErrorKind::DisplayVersion);
    }

    #[test]
    fn built_in_help_subcommand_parses() {
        assert!(
            Cli::try_parse_from(["corulix", "help"]).is_ok() || {
                // clap's auto-generated `help` subcommand renders and returns a
                // `DisplayHelp`-kind "error" rather than a normal `Ok`, exactly
                // like `--help` -- either shape is acceptable here.
                matches!(
                    Cli::try_parse_from(["corulix", "help"]),
                    Err(error) if error.kind() == ErrorKind::DisplayHelp
                )
            }
        );
    }

    #[test]
    fn nested_help_subcommand_forms_parse() {
        for args in [
            vec!["corulix", "help", "toolchain"],
            vec!["corulix", "help", "toolchain", "status"],
            vec!["corulix", "help", "languages"],
            vec!["corulix", "help", "languages", "list"],
            vec!["corulix", "help", "workspace"],
            vec!["corulix", "help", "workspace", "detect"],
            vec!["corulix", "help", "workspace", "inspect"],
            vec!["corulix", "help", "parse"],
            vec!["corulix", "help", "mcp"],
            vec!["corulix", "help", "mcp", "stdio"],
            vec!["corulix", "help", "setup"],
        ] {
            let result = Cli::try_parse_from(&args);
            let accepted = result.is_ok()
                || matches!(&result, Err(error) if error.kind() == ErrorKind::DisplayHelp);
            assert!(
                accepted,
                "expected {args:?} to be accepted as help, got {result:?}"
            );
        }
    }

    #[test]
    fn every_subcommand_help_flag_exits_zero_equivalent() {
        assert_help_or_version(&["corulix", "toolchain", "--help"], ErrorKind::DisplayHelp);
        assert_help_or_version(
            &["corulix", "toolchain", "status", "--help"],
            ErrorKind::DisplayHelp,
        );
        assert_help_or_version(&["corulix", "languages", "--help"], ErrorKind::DisplayHelp);
        assert_help_or_version(
            &["corulix", "languages", "list", "--help"],
            ErrorKind::DisplayHelp,
        );
        assert_help_or_version(&["corulix", "workspace", "--help"], ErrorKind::DisplayHelp);
        assert_help_or_version(
            &["corulix", "workspace", "detect", "--help"],
            ErrorKind::DisplayHelp,
        );
        assert_help_or_version(
            &["corulix", "workspace", "inspect", "--help"],
            ErrorKind::DisplayHelp,
        );
        assert_help_or_version(&["corulix", "parse", "--help"], ErrorKind::DisplayHelp);
        assert_help_or_version(&["corulix", "mcp", "--help"], ErrorKind::DisplayHelp);
        assert_help_or_version(
            &["corulix", "mcp", "stdio", "--help"],
            ErrorKind::DisplayHelp,
        );
    }

    #[test]
    fn legacy_positional_forms_are_rejected() {
        let legacy_invocations: &[&[&str]] = &[
            &["corulix", "languages", "/some/path"],
            &["corulix", "workspace", "inspect", "/some/path"],
            &["corulix", "parse", "/some/workspace", "src/main.rs"],
            &["corulix", "mcp", "stdio", "/some/workspace"],
            &["corulix", "doctor"],
        ];
        for args in legacy_invocations {
            assert!(
                Cli::try_parse_from(*args).is_err(),
                "expected rejection for {args:?}"
            );
        }
    }

    #[test]
    fn canonical_forms_parse_successfully() {
        assert!(Cli::try_parse_from(["corulix", "languages", "list"]).is_ok());
        assert!(Cli::try_parse_from(["corulix", "workspace", "inspect"]).is_ok());
        assert!(
            Cli::try_parse_from(["corulix", "workspace", "detect", "--workspace", "/tmp"]).is_ok()
        );
        assert!(Cli::try_parse_from(["corulix", "parse", "src/main.rs"]).is_ok());
        assert!(Cli::try_parse_from(["corulix", "mcp", "stdio"]).is_ok());
    }

    #[test]
    fn workspace_and_workspace_file_are_mutually_exclusive() {
        let result = Cli::try_parse_from([
            "corulix",
            "workspace",
            "inspect",
            "--workspace",
            "/a",
            "--workspace-file",
            "/b.code-workspace",
        ]);
        assert!(matches!(result, Err(error) if error.kind() == ErrorKind::ArgumentConflict));
    }

    #[test]
    fn single_root_parse_syntax_parses() {
        let result = Cli::try_parse_from([
            "corulix",
            "parse",
            "src/main.rs",
            "--workspace",
            "/srv/project",
        ]);
        assert!(result.is_ok());
    }

    #[test]
    fn multi_root_parse_with_root_selector_parses() {
        let result = Cli::try_parse_from([
            "corulix",
            "parse",
            "src/main.rs",
            "--workspace-file",
            "./Project.code-workspace",
            "--workspace-root",
            "api",
        ]);
        assert!(result.is_ok());
    }

    #[test]
    fn multi_root_workspace_inspect_syntax_parses() {
        let result = Cli::try_parse_from([
            "corulix",
            "workspace",
            "inspect",
            "--workspace-file",
            "./Project.code-workspace",
        ]);
        assert!(result.is_ok());
    }

    #[test]
    fn workspace_detect_syntax_parses() {
        assert!(Cli::try_parse_from(["corulix", "workspace", "detect"]).is_ok());
    }

    #[test]
    fn mcp_single_root_and_multi_root_launch_syntax_parses() {
        assert!(
            Cli::try_parse_from(["corulix", "mcp", "stdio", "--workspace", "/srv/project"]).is_ok()
        );
        assert!(
            Cli::try_parse_from([
                "corulix",
                "mcp",
                "stdio",
                "--workspace-file",
                "./Project.code-workspace"
            ])
            .is_ok()
        );
    }

    /// F1 fix: `--host-config` parses, is optional (its absence must still
    /// parse), and rejects a second value the same way any other clap
    /// single-valued flag would (this crate never hand-rolls a second
    /// parser for it -- Architecture Rule I).
    #[test]
    fn mcp_stdio_host_config_flag_parses_and_is_optional() {
        assert!(
            Cli::try_parse_from([
                "corulix",
                "mcp",
                "stdio",
                "--workspace",
                "/srv/project",
                "--host-config",
                "/etc/corulix/host.toml",
            ])
            .is_ok()
        );
        // Absence is the documented default (`HostConfig::default()`).
        assert!(
            Cli::try_parse_from(["corulix", "mcp", "stdio", "--workspace", "/srv/project"]).is_ok()
        );
    }

    #[test]
    fn setup_bare_invocation_parses() {
        assert!(Cli::try_parse_from(["corulix", "setup"]).is_ok());
    }

    #[test]
    fn setup_profile_full_and_on_demand_parse() {
        assert!(Cli::try_parse_from(["corulix", "setup", "--profile", "full"]).is_ok());
        assert!(Cli::try_parse_from(["corulix", "setup", "--profile", "on-demand"]).is_ok());
    }

    #[test]
    fn setup_rejects_an_unrecognized_profile_value() {
        let result = Cli::try_parse_from(["corulix", "setup", "--profile", "selective"]);
        assert!(matches!(result, Err(error) if error.kind() == ErrorKind::InvalidValue));
    }

    #[test]
    fn setup_only_accepts_repeated_and_comma_delimited_groups() {
        let repeated =
            Cli::try_parse_from(["corulix", "setup", "--only", "rust", "--only", "python"]);
        assert!(repeated.is_ok());
        let comma_delimited = Cli::try_parse_from(["corulix", "setup", "--only", "rust,python"]);
        assert!(comma_delimited.is_ok());
        let Ok(Cli {
            command: Command::Setup { only, .. },
        }) = comma_delimited
        else {
            unreachable!("setup --only rust,python must parse into Command::Setup");
        };
        assert_eq!(only, vec!["rust".to_string(), "python".to_string()]);
    }

    #[test]
    fn setup_exclude_flag_parses() {
        assert!(Cli::try_parse_from(["corulix", "setup", "--exclude", "python"]).is_ok());
    }

    #[test]
    fn setup_help_flag_exits_zero_equivalent() {
        assert_help_or_version(&["corulix", "setup", "--help"], ErrorKind::DisplayHelp);
    }

    /// The command model's own public inventory -- used by the enterprise
    /// help audit to prove help documents only real, current commands.
    #[test]
    fn command_inventory_matches_expected_public_surface() {
        let command = Cli::command();
        let names: Vec<&str> = command
            .get_subcommands()
            .map(clap::Command::get_name)
            .collect();
        for expected in [
            "toolchain",
            "languages",
            "workspace",
            "parse",
            "mcp",
            "setup",
        ] {
            assert!(
                names.contains(&expected),
                "missing expected top-level command: {expected}"
            );
        }
        for forbidden in [
            "doctor",
            "search",
            "format_preview",
            "begin_change",
            "submit_edit",
            "validate_change",
            "semantic",
        ] {
            assert!(
                !names.contains(&forbidden),
                "forbidden command present in inventory: {forbidden}"
            );
        }
    }
}
