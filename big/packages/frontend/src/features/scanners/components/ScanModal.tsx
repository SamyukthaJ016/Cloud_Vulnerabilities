import { useState } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import Form from '@rjsf/core';
import validator from '@rjsf/validator-ajv8';
import type { RJSFSchema } from '@rjsf/utils';
import { AlertCircle, Loader2, Play, X } from 'lucide-react';
import { toast } from 'sonner';
import type { ScannerDto } from '@cloudguard/shared';
import { useRunScan } from '@/features/scans/api/scans.api';
import { cgTemplates } from './rjsf-templates';

interface ScanModalProps {
  scanner: ScannerDto | null;
  onClose: () => void;
}

export function ScanModal({ scanner, onClose }: ScanModalProps) {
  const runScan = useRunScan();
  const [formError, setFormError] = useState<string | null>(null);

  const open = !!scanner;
  const schema = (scanner?.credentialSchema ?? {}) as RJSFSchema;

  return (
    <Dialog.Root
      open={open}
      onOpenChange={(o) => {
        if (!o) {
          setFormError(null);
          onClose();
        }
      }}
    >
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0" />
        <Dialog.Content className="fixed left-1/2 top-1/2 z-50 w-[calc(100vw-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-xl border bg-background shadow-xl data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95">
          {/* Header */}
          <div className="flex items-start justify-between gap-4 border-b px-6 py-4">
            <div className="flex items-start gap-3">
              {scanner?.iconUrl ? (
                <img
                  src={scanner.iconUrl}
                  alt=""
                  className="h-10 w-10 shrink-0 rounded"
                />
              ) : (
                <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded bg-primary/10 text-primary">
                  <Play className="h-4 w-4" />
                </div>
              )}
              <div className="min-w-0">
                <Dialog.Title className="text-base font-semibold leading-tight">
                  Run scan
                </Dialog.Title>
                {scanner && (
                  <Dialog.Description className="mt-0.5 text-sm text-muted-foreground">
                    {scanner.name}
                    {scanner.category && (
                      <span className="ml-1.5 rounded bg-muted px-1.5 py-0.5 text-[10px] uppercase tracking-wide">
                        {scanner.category}
                      </span>
                    )}
                  </Dialog.Description>
                )}
              </div>
            </div>
            <Dialog.Close
              className="rounded p-1 text-muted-foreground hover:bg-muted hover:text-foreground"
              aria-label="Close"
            >
              <X className="h-4 w-4" />
            </Dialog.Close>
          </div>

          {/* Body */}
          {scanner && (
            <div className="px-6 py-5">
              {scanner.description && (
                <p className="mb-4 text-sm text-muted-foreground">{scanner.description}</p>
              )}

              {formError && (
                <div className="mb-4 flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-destructive">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
                  <span>{formError}</span>
                </div>
              )}

              <Form
                schema={schema}
                validator={validator}
                templates={cgTemplates}
                disabled={runScan.isPending}
                showErrorList={false}
                onSubmit={async ({ formData }) => {
                  setFormError(null);
                  try {
                    const { jobId } = await runScan.mutateAsync({
                      scannerKey: scanner.key,
                      credentials: formData ?? {},
                    });
                    toast.success('Scan started', {
                      description: `Job ${jobId.slice(0, 8)}…`,
                    });
                    onClose();
                  } catch (err) {
                    const message =
                      err instanceof Error ? err.message : 'Failed to start scan';
                    setFormError(message);
                  }
                }}
              >
                <div className="-mx-6 -mb-5 mt-2 flex justify-end gap-2 border-t bg-muted/30 px-6 py-3">
                  <Dialog.Close className="rounded-md border bg-background px-3 py-2 text-sm font-medium hover:bg-muted">
                    Cancel
                  </Dialog.Close>
                  <button
                    type="submit"
                    disabled={runScan.isPending}
                    className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
                  >
                    {runScan.isPending ? (
                      <>
                        <Loader2 className="h-4 w-4 animate-spin" /> Starting…
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4" /> Run scan
                      </>
                    )}
                  </button>
                </div>
              </Form>
            </div>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
