import { computeLabel } from "./rename_module";

export function Widget(props: { name: string }) {
  const label = computeLabel(props.name);
  return <span title={computeLabel(label)}>{label}</span>;
}
