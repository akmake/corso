const ROLE_ORDER = ['viewer', 'editor', 'admin'];

function normalizeRole(role) {
  if (!role) return null;
  const normalized = String(role).trim().toLowerCase();
  return ROLE_ORDER.includes(normalized) ? normalized : null;
}

export function attachUserContext(req, res, next) {
  const configuredDefaultRole = normalizeRole(process.env.DEFAULT_APP_ROLE) || 'admin';
  const configuredDefaultName = process.env.DEFAULT_APP_USER || 'local-user';

  const roleFromHeader = normalizeRole(req.header('X-User-Role'));
  const nameFromHeader = req.header('X-User-Name');

  req.user = {
    role: roleFromHeader || configuredDefaultRole,
    name: nameFromHeader || configuredDefaultName,
  };

  next();
}

export function requireRole(minimumRole) {
  const minimumIndex = ROLE_ORDER.indexOf(minimumRole);

  return (req, res, next) => {
    const currentRole = req.user?.role || 'viewer';
    const currentIndex = ROLE_ORDER.indexOf(currentRole);

    if (currentIndex < minimumIndex) {
      return res.status(403).json({
        message: `This action requires ${minimumRole} permissions`,
        currentRole,
      });
    }

    return next();
  };
}

export function getRoleOrder() {
  return [...ROLE_ORDER];
}
