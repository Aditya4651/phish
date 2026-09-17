import { URLScanResult } from '../types';
import { analyzeURL } from './phishingEngine';

export function classifyURL(rawUrl: string): URLScanResult {
  return analyzeURL(rawUrl);
}
