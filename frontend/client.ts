/**
 * Simple API client for Email Scanner
 */
import {
  EmailScanRequest,
  CompleteScanResponse,
  HealthResponse
} from './types';

export class EmailScannerClient {
  private baseUrl: string;
  private apiKey?: string;

  constructor(baseUrl: string = 'http://localhost:8000', apiKey?: string) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.apiKey = apiKey;
  }

  private async request<T>(
    endpoint: string,
    method: string = 'GET',
    body?: any
  ): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
    };

    if (this.apiKey) {
      headers['X-API-Key'] = this.apiKey;
    }

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method,
      headers,
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({ detail: 'Unknown error' }));
      throw new Error(errorData.detail || `API request failed: ${response.status}`);
    }

    return response.json();
  }

  /**
   * Check if the API is healthy
   */
  async checkHealth(): Promise<HealthResponse> {
    return this.request<HealthResponse>('/health');
  }

  /**
   * Perform a complete scan of an email
   */
  async scanEmail(data: EmailScanRequest): Promise<CompleteScanResponse> {
    return this.request<CompleteScanResponse>('/api/scan', 'POST', data);
  }

  /**
   * Scan only the email address
   */
  async scanEmailAddress(emailAddress: string): Promise<any> {
    return this.request('/api/scan/email-address', 'POST', { email_address: emailAddress });
  }

  /**
   * Scan only the URLs in text
   */
  async scanUrls(emailText: string): Promise<any> {
    return this.request('/api/scan/urls', 'POST', { email_text: emailText });
  }

  /**
   * Analyze email content only
   */
  async scanContent(emailText: string): Promise<any> {
    return this.request('/api/scan/content', 'POST', { email_text: emailText });
  }
}
