import { URLScanResult } from '../types';
import { analyzeURL } from './phishingEngine';
export * from './mlPipeline';
export * from './tldExtract';

export function classifyURL(rawUrl: string, scannedBy: string = 'Production ML Model'): URLScanResult {
  return analyzeURL(rawUrl, scannedBy);
}
