const ROLE_KEY = 'myvisit-role';
const NAME_KEY = 'myvisit-user-name';

export function getUserRole() {
  if (typeof window === 'undefined') return 'admin';
  return window.localStorage.getItem(ROLE_KEY) || 'admin';
}

export function setUserRole(role) {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(ROLE_KEY, role);
}

export function getUserName() {
  if (typeof window === 'undefined') return 'local-user';
  return window.localStorage.getItem(NAME_KEY) || 'local-user';
}

export function setUserName(name) {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(NAME_KEY, name || 'local-user');
}
