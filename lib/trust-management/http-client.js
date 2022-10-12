import HttpClient from '../../../utils/http-client';

export const httpClient = HttpClient({ baseURL: process.env.TRUST_MANAGEMENT_SERVICE_URL });
