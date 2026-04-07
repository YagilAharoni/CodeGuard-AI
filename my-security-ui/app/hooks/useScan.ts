import { useState } from 'react';
import axios, { AxiosError } from 'axios';

// Define the required types based on the FastAPI response structure
export interface Finding {
  file_name: string;
  issue_description: string;
  suggested_fix: string;
  source_code?: string;
  fixed_code?: string;
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

export interface DependencyAdvisory {
  id: string;
  summary: string;
  severity: string;
  fixed_in: string | null;
  url: string;
}

export interface VulnerablePackage {
  package: string;
  ecosystem: string;
  advisory_count: number;
  advisories: DependencyAdvisory[];
}

export interface SafePackage {
  package: string;
  ecosystem: string;
}

export interface DependencyScanResult {
  vulnerable: VulnerablePackage[];
  safe: SafePackage[];
  skipped_stdlib_count: number;
  total_checked: number;
}

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export const useScan = (apiUrl: string = API_URL) => {
  const [isScanning, setIsScanning] = useState(false);
  const [results, setResults] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [depResults, setDepResults] = useState<DependencyScanResult | null>(null);
  const [isDepScanning, setIsDepScanning] = useState(false);

  const uploadFile = async (files: File | FileList | File[], persona: string = 'Student', apiKey?: string, provider?: string, username?: string) => {
    setIsScanning(true);
    setResults(null);
    setError(null);

    const formData = new FormData();
    
    const fileArray = files instanceof File ? [files] : Array.from(files);
    fileArray.forEach((file: File) => {
      // Use webkitRelativePath for folder structure preservation, fall back to .name for single files
      const fileName = (file as any).webkitRelativePath || file.name;
      formData.append('files', file, fileName);
    });
    
    formData.append('persona', persona);
    
    if (apiKey) {
      formData.append('api_key', apiKey);
    }

    if (provider) {
      formData.append('provider', provider);
    }

    if (username) {
      formData.append('username', username);
    }

    try {
      const response = await axios.post<ScanResult>(`${apiUrl}/analyze`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          'X-User': username || 'anonymous'
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

  const scanGithubUrl = async (githubUrl: string, persona: string = 'Student', apiKey?: string, provider?: string, username?: string) => {
    setIsScanning(true);
    setResults(null);
    setError(null);

    const formData = new FormData();
    formData.append('github_url', githubUrl);
    formData.append('persona', persona);
    
    if (apiKey) {
      formData.append('api_key', apiKey);
    }

    if (provider) {
      formData.append('provider', provider);
    }

    if (username) {
      formData.append('username', username);
    }

    try {
      const response = await axios.post<ScanResult>(`${apiUrl}/analyze-github`, formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          'X-User': username || 'anonymous'
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
            'An error occurred during github analysis.'
          );
        }
      } else {
        setError('An unexpected error occurred.');
      }
    } finally {
      setIsScanning(false);
    }
  };

  const downloadReport = async (reportId: string, username?: string) => {
    if (!reportId) return;
    
    try {
      const params: Record<string, string> = { report_id: reportId };
      if (username) params.username = username;
      
      const response = await axios.get(`${apiUrl}/export-pdf`, {
        params,
        responseType: 'blob',
        headers: {
          'X-User': username || 'anonymous'
        }
      });

      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      
      // Try to get filename from Content-Disposition header
      const contentDisposition = response.headers['content-disposition'];
      let filename = `security_report_${reportId.substring(0, 8)}.pdf`;
      
      if (contentDisposition) {
        const match = contentDisposition.match(/filename="?([^"]+)"?/);
        if (match && match[1]) {
          filename = match[1];
        }
      } else {
        // Fallback to a date-based name if header is missing
        const now = new Date();
        const timestamp = now.getFullYear() + "-" + 
                          String(now.getMonth() + 1).padStart(2, '0') + "-" + 
                          String(now.getDate()).padStart(2, '0') + "_" + 
                          String(now.getHours()).padStart(2, '0') + "-" + 
                          String(now.getMinutes()).padStart(2, '0');
        filename = `Security_Report_${timestamp}.pdf`;
      }
      
      link.setAttribute('download', filename);
      document.body.appendChild(link);
      link.click();
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

  const scanDependencies = async (files: File | FileList | File[]) => {
    setIsDepScanning(true);
    setDepResults(null);
    const formData = new FormData();
    const fileArray = files instanceof File ? [files] : Array.from(files);
    fileArray.forEach((file: File) => {
      formData.append('files', file, (file as any).webkitRelativePath || file.name);
    });
    try {
      const response = await axios.post<DependencyScanResult>(`${apiUrl}/scan-dependencies`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setDepResults(response.data);
    } catch (err: any) {
      if (axios.isAxiosError(err) && err.response?.status === 429) {
        setError('Rate limit reached. Please wait before scanning dependencies.');
      } else {
        setError('Dependency scan failed. Please try again.');
      }
    } finally {
      setIsDepScanning(false);
    }
  };

  return {
    uploadFile,
    scanGithubUrl,
    downloadReport,
    scanDependencies,
    isScanning,
    isDepScanning,
    results,
    depResults,
    error,
    clearError: () => setError(null),
    clearResults: () => { setResults(null); setDepResults(null); }
  };
};
