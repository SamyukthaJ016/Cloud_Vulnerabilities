import type { ChangeEvent, FocusEvent } from 'react';
import { AlertCircle } from 'lucide-react';
import type {
  BaseInputTemplateProps,
  ErrorListProps,
  FieldTemplateProps,
  RJSFSchema,
  StrictRJSFSchema,
  FormContextType,
} from '@rjsf/utils';
import {
  ariaDescribedByIds,
  examplesId,
  getInputProps,
} from '@rjsf/utils';

/**
 * Tailwind-styled RJSF template overrides that match the rest of the app.
 * Pulled into ScanModal via the `templates` prop.
 */

export function FieldTemplate<
  T = unknown,
  S extends StrictRJSFSchema = RJSFSchema,
  F extends FormContextType = FormContextType,
>(props: FieldTemplateProps<T, S, F>) {
  const {
    id,
    classNames,
    label,
    children,
    rawErrors = [],
    rawHelp,
    rawDescription,
    hidden,
    required,
    displayLabel,
  } = props;

  if (hidden) return <div className="hidden">{children}</div>;

  return (
    <div className={`mb-4 ${classNames ?? ''}`}>
      {displayLabel && label && (
        <label
          htmlFor={id}
          className="mb-1.5 block text-sm font-medium text-foreground"
        >
          {label}
          {required && <span className="ml-0.5 text-destructive">*</span>}
        </label>
      )}
      {displayLabel && rawDescription && (
        <p className="mb-1.5 text-xs text-muted-foreground">{rawDescription}</p>
      )}
      {children}
      {rawErrors.length > 0 && (
        <ul className="mt-1.5 space-y-0.5">
          {rawErrors.map((err, i) => (
            <li key={i} className="flex items-start gap-1 text-xs text-destructive">
              <AlertCircle className="mt-0.5 h-3 w-3 shrink-0" /> {err}
            </li>
          ))}
        </ul>
      )}
      {rawHelp && <p className="mt-1.5 text-xs text-muted-foreground">{rawHelp}</p>}
    </div>
  );
}

export function BaseInputTemplate<
  T = unknown,
  S extends StrictRJSFSchema = RJSFSchema,
  F extends FormContextType = FormContextType,
>(props: BaseInputTemplateProps<T, S, F>) {
  const {
    id,
    value,
    placeholder,
    required,
    disabled,
    readonly,
    autofocus,
    onBlur,
    onFocus,
    onChange,
    onChangeOverride,
    options,
    schema,
    rawErrors = [],
    type,
  } = props;

  const inputProps = {
    ...getInputProps<T, S, F>(schema, type, options),
  };

  const _onChange = (event: ChangeEvent<HTMLInputElement>) => {
    const v = event.target.value;
    if (onChangeOverride) {
      onChangeOverride(event);
    } else {
      onChange(v === '' ? options.emptyValue : v);
    }
  };

  const _onBlur = (event: FocusEvent<HTMLInputElement>) => onBlur(id, event.target.value);
  const _onFocus = (event: FocusEvent<HTMLInputElement>) => onFocus(id, event.target.value);

  const errored = rawErrors.length > 0;

  return (
    <input
      id={id}
      list={schema.examples ? examplesId<T>(id) : undefined}
      placeholder={placeholder}
      autoFocus={autofocus}
      required={required}
      disabled={disabled}
      readOnly={readonly}
      aria-describedby={ariaDescribedByIds<T>(id, !!schema.examples)}
      className={`block w-full rounded-md border bg-background px-3 py-2 text-sm shadow-sm transition focus:outline-none focus:ring-2 focus:ring-primary/40 disabled:cursor-not-allowed disabled:opacity-50 ${
        errored ? 'border-destructive focus:ring-destructive/40' : 'border-input'
      }`}
      {...inputProps}
      value={value == null ? '' : (value as string | number)}
      onChange={_onChange}
      onBlur={_onBlur}
      onFocus={_onFocus}
    />
  );
}

export function ErrorListTemplate({ errors }: ErrorListProps) {
  if (!errors?.length) return null;
  return (
    <div className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
      <p className="mb-1 font-medium">Please fix the highlighted fields:</p>
      <ul className="list-disc space-y-0.5 pl-5 text-xs">
        {errors.map((e, i) => (
          <li key={i}>{e.stack}</li>
        ))}
      </ul>
    </div>
  );
}

export const cgTemplates = {
  FieldTemplate,
  BaseInputTemplate,
  ErrorListTemplate,
};
