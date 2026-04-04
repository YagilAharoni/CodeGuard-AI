import { useState } from 'react';
import axios, { AxiosError } from 'axios';

// Define the required types based on the FastAPI response structure
export interface Finding {
  file_name: string;
  issue_description: string;
  suggested_fix: string;
}

export interface Stats {
  High: number;
  Medium: number;
  Low: number;
}

export interface ScanResult {
  report_id: string;
  status: 'SAFE' | 'VULNERABLE' | 'ERROR';
  stats: Stats;
  findings: Finding[];
  improvement_suggestions?: string[];
}

export const useScan = (apiUrl: string = 'http://localhost:8000') => {
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const uploadFile = async (files: File | FileList | File[], persona: string = 'Student', apiKey?: string, provider?: string) => {
    setIsScanning(true);
    setResults(null);
    setError(null);

    const formData = new FormData();
    
    const fileArray = files instanceof File ? [files] : Array.from(files);
    fileArray.forEach(file => {
      formData.append('files', file);
    });
    
    formData.append('persona', persona);
    
    if (apiKey) {
      formData.append('api_key', apiKey);
    }

    if (provider) {
      formData.append('provider', provider);
    }

    try {
      const response = await axios.post<ScanResult>(`${apiUrl}/analyze`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });

      setResults(response.data);
    } catch (err: any) {
      if (axios.isAxiosError(err)) {
        const axiosError = err as AxiosError;
        if (axiosError.response?.status === 429) {
          setError('Cool-down active, please wait. You are sending too many requests.');
        } else {
          setError(
            (axiosError.response?.data as any)?.detail ||
            axiosError.message ||
            'An error occurred during analysis.'
          );
        }
      } else {
        setError('An unexpected error occurred.');
      }
    } finally {
      setIsScanning(false);
    }
  };

  const downloadReport = async (reportId: string) => {
    if (!reportId) return;
    
    try {
      const response = await axios.get(`${apiUrl}/export-pdf`, {
        params: { report_id: reportId },
        responseType: 'blob', // Important: This tells axios to expect binary data
      });

      // Create a URL for the blob
      const url = window.URL.createObjectURL(new Blob([response.data]));
      
      // Create a hidden link element and click it to trigger download
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `security_report_${reportId.substring(0, 8)}.pdf`);
      document.body.appendChild(link);
      link.click();
      
      // Cleanup
      link.parentNode?.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      if (axios.isAxiosError(err) && err.response?.status === 429) {
        setError('Cool-down active. Slow down report downloads.');
      } else {
         console.error('Failed to download report', err);
         setError('Failed to download report. It may have expired.');
      }
    }
  };

  return {
    uploadFile,
    downloadReport,
    isScanning,
    results,
    error,
    clearError: () => setError(null),
    clearResults: () => setResults(null)
  };
};
