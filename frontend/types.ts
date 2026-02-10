/**
 * TypeScript definitions for Email Scanner API
 */

export interface EmailScanRequest {
  email_address?: string;
  email_text?: string;
}

export interface EmailVerificationResult {
  valid: boolean;
  score: number;
  disposable: boolean;
  webmail: boolean;
  accept_all: boolean;
  gibberish: boolean;
  risk_score: number;
  details?: Record<string, any>;
}

export interface URLScanResult {
  urls_found: string[];
  malicious_count: number;
  suspicious_count: number;
  risk_score: number;
  details?: any[];
}

export interface ContentAnalysisResult {
  prediction: string;
  confidence: number;
  risk_score: number;
  is_phishing: boolean;
}

export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface CompleteScanResponse {
  scam_score: number;
  risk_level: RiskLevel;
  labels: string[];
  recommendations: string[];
  email_verification?: EmailVerificationResult;
  url_scan?: URLScanResult;
  content_analysis?: ContentAnalysisResult;
}

export interface HealthResponse {
  status: string;
  ml_model_loaded: boolean;
}
