import { hasDwgConverter } from '../utils/dwgConverter.js';
import { getRoleOrder } from '../middlewares/authMiddleware.js';

export const getCapabilities = async (req, res) => {
  const dwgImportAvailable = await hasDwgConverter();

  res.json({
    dwgImportAvailable,
    pdfImportAvailable: true,
    authMode: 'header-role',
    supportedRoles: getRoleOrder(),
    currentRole: req.user?.role || 'viewer',
    currentUser: req.user?.name || 'anonymous',
  });
};
