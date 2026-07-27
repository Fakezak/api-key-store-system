const { body, validationResult } = require('express-validator');

const validateApiKey = [
    body('storeId').isString().notEmpty().withMessage('Store ID is required'),
    body('storeName').isString().notEmpty().withMessage('Store name is required'),
    body('permissions').optional().isArray().withMessage('Permissions must be an array'),
    body('environment').optional().isIn(['development', 'staging', 'production']),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }
        next();
    }
];

const validateKeyUpdate = [
    body('name').optional().isString(),
    body('description').optional().isString(),
    body('permissions').optional().isArray(),
    body('status').optional().isIn(['active', 'inactive', 'revoked']),
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                errors: errors.array()
            });
        }
        next();
    }
];

module.exports = {
    validateApiKey,
    validateKeyUpdate
};
