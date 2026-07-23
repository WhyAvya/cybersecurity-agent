import { useQuery } from '@tanstack/react-query';
import { apiClient } from './client';
import type { ScanState } from '../types/api';

export const terminalScanStates = new Set<ScanState>(['completed', 'failed', 'cancelled', 'completed_with_errors']);

export function useHealth() {
  return useQuery({
    queryKey: ['health'],
    queryFn: apiClient.getHealth,
    refetchInterval: 30_000,
  });
}

export function useConfig() {
  return useQuery({
    queryKey: ['config'],
    queryFn: apiClient.getConfig,
  });
}

export function useFrozenEvaluation() {
  return useQuery({
    queryKey: ['frozen-evaluation'],
    queryFn: apiClient.getFrozenEvaluation,
  });
}

export function useScan(scanId: string | undefined) {
  return useQuery({
    queryKey: ['scan', scanId],
    queryFn: () => apiClient.getScan(scanId ?? ''),
    enabled: Boolean(scanId),
    refetchInterval: (query) => {
      const state = query.state.data?.state;
      return state && terminalScanStates.has(state) ? false : 1500;
    },
  });
}

export function useScanResult(scanId: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ['scan-result', scanId],
    queryFn: () => apiClient.getScanResult(scanId ?? ''),
    enabled: Boolean(scanId) && enabled,
  });
}

export function useArtifacts(scanId: string | undefined, enabled: boolean) {
  return useQuery({
    queryKey: ['scan-artifacts', scanId],
    queryFn: () => apiClient.getArtifacts(scanId ?? ''),
    enabled: Boolean(scanId) && enabled,
  });
}
