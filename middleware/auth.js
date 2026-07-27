const jwt = require('jsonwebtoken');
const ApiKey = require('../models/ApiKey');

// JWT Authentication (for admin users)
const authenticate = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        
        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Authentication required'
            });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secret_key');
        req.user = decoded;
        next();
    } catch (error) {
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                message: 'Invalid token'
            });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                message: 'Token expired'
            });
        }
        next(error);
    }
};

// API Key Authentication (for API access)
const authenticateApiKey = async (req, res, next) => {
    try {
        const apiKey = req.headers['x-api-key'];
        
        if (!apiKey) {
            return res.status(401).json({
                success: false,
                message: 'API key required'
            });
        }

        const keyRecord = await ApiKey.findOne({ 
            apiKey,
            status: 'active',
            expiresAt: { $gt: new Date() }
        });

        if (!keyRecord) {
            return res.status(401).json({
                success: false,
                message: 'Invalid or expired API key'
            });
        }

        // Check rate limits
        // Implement rate limiting logic here

        await keyRecord.incrementUsage();
        req.apiKey = keyRecord;
        next();
    } catch (error) {
        next(error);
    }
};

// Authorization middleware
const authorize = (permissions = []) => {
    return (req, res, next) => {
        try {
            // Check if user has required permissions
            const userPermissions = req.user?.permissions || [];
            
            if (typeof permissions === 'string') {
                permissions = [permissions];
            }

            const hasPermission = permissions.every(p => userPermissions.includes(p));
            
            if (!hasPermission) {
                return res.status(403).json({
                    success: false,
                    message: 'Insufficient permissions'
                });
            }

            next();
        } catch (error) {
            next(error);
        }
    };
};

module.exports = {
    authenticate,
    authenticateApiKey,
    authorize
};
