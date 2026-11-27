interface ToggleSwitchProps {
  checked: boolean;
  onChange: (next: boolean) => void;
  disabled?: boolean;
  title?: string;
}

export function ToggleSwitch({
  checked,
  onChange,
  disabled,
  title,
}: ToggleSwitchProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      title={title}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full transition-colors duration-150 focus:outline-none disabled:opacity-50 ${
        checked
          ? "bg-blue-500"
          : "bg-gray-300 dark:bg-white/20"
      }`}
    >
      <span
        className={`inline-block h-4 w-4 transform rounded-full bg-white shadow-sm transition-transform duration-150 ${
          checked ? "translate-x-[18px]" : "translate-x-[2px]"
        }`}
      />
    </button>
  );
}
