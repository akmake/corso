import axios from 'axios';

const client = axios.create({
  baseURL: 'http://localhost:8000',
  headers: { 'Content-Type': 'application/json' },
});

const _auth = (cookies, token) => ({
  cookies:    cookies || '',
  auth_token: token   || '',
});

export const startScan = {
  domain:      (domain)   => client.post('/api/v1/scan/domain',      { url: domain }),
  deep_domain: (target)   => client.post('/api/v1/scan/deep_domain', { target }),
  web:         (url)      => client.post('/api/v1/scan/web',         { url }),
  quick:       (host)     => client.post('/api/v1/scan/quick',       { target: host }),
  network:     ()         => client.post('/api/v1/scan/network'),
  username:    (username) => client.post('/api/v1/scan/username',    { target: username }),
  torSearch:   (query)    => client.post('/api/v1/scan/torSearch',   { query }),
  audit:       (url)      => client.post('/api/v1/scan/audit',       { url }),
  investigate: (query)    => client.post('/api/v1/scan/investigate', { query }),
  graph:       (query)    => client.post('/api/v1/scan/graph',       { target: query }),
  dossier:     (query)    => client.post('/api/v1/scan/dossier',     { query }),
  siteSearch:  (url, name) => client.post('/api/v1/scan/siteSearch', { url, query: name }),
  israeli:     (query)    => client.post('/api/v1/scan/israeli',     { target: query }),
  guidestar:   (query)    => client.post('/api/v1/scan/guidestar',   { target: query }),
  dirfuzz:        (url, cookies, token) => client.post('/api/v1/scan/dirfuzz',        { url, ..._auth(cookies, token) }),
  idor:           (url)                 => client.post('/api/v1/scan/idor',           { url }),
  ssrf:           (url)                 => client.post('/api/v1/scan/ssrf',           { url }),
  authtest:       (url, cookies, token) => client.post('/api/v1/scan/authtest',       { url, ..._auth(cookies, token) }),
  bizlogic:       (url, cookies, token) => client.post('/api/v1/scan/bizlogic',       { url, ..._auth(cookies, token) }),
  baas:           (url)                 => client.post('/api/v1/scan/baas',           { url }),
  pentest:        (url)                 => client.post('/api/v1/scan/pentest',        { url }),
  fullscan:       (url)                 => client.post('/api/v1/scan/fullscan',       { url }),
  fullpentest:    (url, cookies, token) => client.post('/api/v1/scan/fullpentest',    { url, ..._auth(cookies, token) }),
  adaptive:       (url)                 => client.post('/api/v1/scan/adaptive',       { url }),
  email:          (email)               => client.post('/api/v1/scan/email',          { target: email }),
  breach:         (email)               => client.post('/api/v1/scan/breach',         { target: email }),
  secrets:        (url, cookies, token) => client.post('/api/v1/scan/secrets',        { url, ..._auth(cookies, token) }),
  // New scanners
  xss:            (url)                 => client.post('/api/v1/scan/xss',            { url }),
  sqli:           (url)                 => client.post('/api/v1/scan/sqli',           { url }),
  jwt:            (url, token = '')     => client.post('/api/v1/scan/jwt',            { url, query: token }),
  ssl:            (url)                 => client.post('/api/v1/scan/ssl',            { url }),
  massassignment: (url)                 => client.post('/api/v1/scan/massassignment', { url }),
  takeover:       (url)                 => client.post('/api/v1/scan/takeover',       { url }),
  nuclei:         (url, severity)       => client.post('/api/v1/scan/nuclei',         { url, query: severity }),
  fileupload:     (url)                 => client.post('/api/v1/scan/fileupload',      { url }),
  authscan:       (url, cookies, token) => client.post('/api/v1/scan/authscan',       { url, ..._auth(cookies, token) }),
  exploit:        (url, cookies, token, skipPhases='') => client.post('/api/v1/scan/exploit', { url, query: skipPhases, ..._auth(cookies, token) }),
};

export const getJob       = (jobId) => client.get(`/api/v1/jobs/${jobId}`);
export const getTorStatus = ()      => client.get('/api/v1/tor/status');
export const getToolsStatus = ()    => client.get('/api/v1/tools/status');

export const reportApi = {
  generate: (payload) => client.post('/api/v1/report/generate', payload, { responseType: 'blob' }),
};

export const casesApi = {
  list:       ()              => client.get('/api/v1/cases'),
  get:        (id)            => client.get(`/api/v1/cases/${id}`),
  updateNotes:(id, notes)     => client.patch(`/api/v1/cases/${id}/notes`, { notes }),
  delete:     (id)            => client.delete(`/api/v1/cases/${id}`),
};

export const videoApi = {
  info:     (url, headers)         => client.post('/api/v1/video/info',     { url, headers }),
  download: (url, format, headers) => client.post('/api/v1/video/download', { url, format, headers }),
  sniff:    (url, timeout)         => client.post('/api/v1/video/sniff',    { url, timeout }),
  list:     ()                     => client.get('/api/v1/video/list'),
  delete:   (filename)             => client.delete(`/api/v1/video/files/${filename}`),
  fileUrl:  (filename)             => `http://localhost:8000/api/v1/video/files/${filename}`,
};

export const videoConverterApi = {
  convertToMp3:   (formData) => client.post('/api/v1/video/convert/mp3',   formData, { headers: { 'Content-Type': 'multipart/form-data' } }),
  convertToAudioMp4: (formData) => client.post('/api/v1/video/convert/audio-mp4', formData, { headers: { 'Content-Type': 'multipart/form-data' } }),
};

export const transcribeApi = {
  transcribeFile: (formData) => client.post('/api/v1/transcribe/file', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
};

export const coursesApi = {
  list:       ()                          => client.get('/api/v1/courses'),
  create:     (name)                      => client.post('/api/v1/courses', { name }),
  delete:     (courseId)                  => client.delete(`/api/v1/courses/${courseId}`),
  addLesson:  (courseId, body)            => client.post(`/api/v1/courses/${courseId}/lessons`, body),
  importLesson: (courseId, title, path)   => client.post(`/api/v1/courses/${courseId}/lessons/import`, { title, path }),
  uploadLesson: (courseId, formData, onProgress) => client.post(
    `/api/v1/courses/${courseId}/lessons/upload`, formData,
    { headers: { 'Content-Type': 'multipart/form-data' }, onUploadProgress: onProgress }
  ),
  deleteLesson: (courseId, lessonId)      => client.delete(`/api/v1/courses/${courseId}/lessons/${lessonId}`),
  transcribe: (courseId, lessonId, body)  => client.post(`/api/v1/courses/${courseId}/lessons/${lessonId}/transcribe`, body),
  videoUrl:   (courseId, lessonId)        => `http://localhost:8000/api/v1/courses/${courseId}/lessons/${lessonId}/video`,
  transcriptUrl: (courseId, lessonId, fmt) => `http://localhost:8000/api/v1/courses/${courseId}/lessons/${lessonId}/transcript/${fmt}`,
  uploadPresentation: (courseId, lessonId, formData) => client.post(
    `/api/v1/courses/${courseId}/lessons/${lessonId}/presentations/upload`, formData,
    { headers: { 'Content-Type': 'multipart/form-data' } }
  ),
  importPresentation: (courseId, lessonId, path) => client.post(
    `/api/v1/courses/${courseId}/lessons/${lessonId}/presentations/import`, { path }
  ),
  deletePresentation: (courseId, lessonId, filename) => client.delete(
    `/api/v1/courses/${courseId}/lessons/${lessonId}/presentations/${encodeURIComponent(filename)}`
  ),
  presentationUrl: (courseId, lessonId, filename) =>
    `http://localhost:8000/api/v1/courses/${courseId}/lessons/${lessonId}/presentations/${encodeURIComponent(filename)}`,
};
