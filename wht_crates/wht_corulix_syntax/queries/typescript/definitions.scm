; SPDX-FileCopyrightText: 2026 WhaTalker Inc.
; SPDX-License-Identifier: AGPL-3.0-only
; Original Corulix query authored from official grammar node types.
(function_declaration name: (identifier) @definition.function)
(class_declaration name: (type_identifier) @definition.class)
(interface_declaration name: (type_identifier) @definition.interface)
(type_alias_declaration name: (type_identifier) @definition.type)
(enum_declaration name: (identifier) @definition.enum)
