import type { LoginResponse, DroidInteractionRequest, DroidInteractionResponse } from '../types';

const API_BASE_URL = '/api';
const REQUEST_TIMEOUT_MS = 8000; // 8 seconds

/**
 * A wrapper around fetch that adds a timeout.
 * @param resource The URL to fetch.
 * @param options Fetch options, including an optional timeout.
 * @returns A Promise that resolves to the Response object.
 */
async function fetchWithTimeout(
  resource: RequestInfo,
  options: RequestInit & { timeout?: number } = {}
): Promise<Response> {
  const { timeout = REQUEST_TIMEOUT_MS } = options;

  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(resource, {
      ...options,
      signal: controller.signal,
    });
    clearTimeout(id);
    return response;
  } catch (error) {
    clearTimeout(id);
    // Re-throw the error to be caught by the calling function
    throw error;
  }
}

/**
 * Handles the response from the API, parsing JSON and throwing errors for non-ok responses.
 * @param response The Response object from fetch.
 * @returns A Promise that resolves to the parsed JSON data.
 */
async function handleResponse<T>(response: Response): Promise<T> {
  const text = await response.text();
  // Handle cases where the response body might be empty
  const data = text ? JSON.parse(text) : {};

  if (!response.ok) {
    const errorMessage = data.error || `HTTP error! status: ${response.status}`;
    throw new Error(errorMessage);
  }

  return data as T;
}

/**
 * A generic function to handle API requests with timeout and error handling.
 * @param endpoint The API endpoint to call.
 * @param options The fetch options.
 * @returns A promise that resolves with the API response data.
 */
async function apiRequest<T>(endpoint: string, options: RequestInit & { timeout?: number } = {}): Promise<T> {
  try {
    const response = await fetchWithTimeout(`${API_BASE_URL}${endpoint}`, options);
    return handleResponse<T>(response);
  } catch (error: any) {
    if (error.name === 'AbortError') {
      throw new Error('Request timed out. The server may be offline or unreachable.');
    }
    // Re-throw other network errors or errors from handleResponse
    throw error;
  }
}

export const login = (username: string, password: string): Promise<LoginResponse> => {
  return apiRequest<LoginResponse>('/auth/login', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username, password }),
  });
};

export const interactWithDroid = (token: string, data: DroidInteractionRequest): Promise<DroidInteractionResponse> => {
  return apiRequest<DroidInteractionResponse>('/droid/interact', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
    },
    body: JSON.stringify(data),
  });
};
