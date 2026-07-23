import { useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../api/client';

export function CancelScanButton({ scanId }: { scanId: string }) {
  const client = useQueryClient();
  const cancel = useMutation({
    mutationFn: () => apiClient.cancelScan(scanId),
    onSuccess: () => void client.invalidateQueries({ queryKey: ['scan', scanId] }),
  });
  return (
    <button className="secondary-action" type="button" disabled={cancel.isPending} onClick={() => cancel.mutate()}>
      {cancel.isPending ? 'Cancellation requested' : 'Cancel Scan'}
    </button>
  );
}
