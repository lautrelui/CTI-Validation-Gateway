const config = require('../config');

/**
 * Validate verification request payload per spec section 3.6.
 */
function validateVerificationRequest(req, res, next) {
  const { verification_request_id, identifier, request_context, options } = req.body;

  // verification_request_id is mandatory (assigned by Central DIT)
  if (!verification_request_id || typeof verification_request_id !== 'string' || !verification_request_id.trim()) {
    return res.status(400).json({
      status: 'error',
      error_code: 'INVALID_VERIFICATION_REQUEST_ID',
      message: 'verification_request_id is required and must be a non-empty string',
    });
  }

  const errors = [];

  // identifier validation
  if (!identifier) {
    errors.push('identifier is required');
  } else {
    if (!identifier.identifier_type) {
      errors.push('identifier.identifier_type is required');
    } else if (!config.supportedIdentifierTypes.includes(identifier.identifier_type)) {
      return res.status(400).json({
        status: 'error',
        error_code: 'UNSUPPORTED_IDENTIFIER_TYPE',
        message: `Unsupported identifier type: ${identifier.identifier_type}. Supported: ${config.supportedIdentifierTypes.join(', ')}`,
      });
    }

    if (!identifier.raw_value) {
      errors.push('identifier.raw_value is required');
    }

    if (!identifier.issuer_country) {
      errors.push('identifier.issuer_country is required');
    }
  }

  // request_context validation
  if (!request_context) {
    errors.push('request_context is required');
  } else {
    if (!request_context.requesting_assujetti_id) errors.push('request_context.requesting_assujetti_id is required');
    if (!request_context.onebox_id) errors.push('request_context.onebox_id is required');
    if (!request_context.purpose) {
      errors.push('request_context.purpose is required');
    } else if (!config.supportedPurposes.includes(request_context.purpose)) {
      errors.push(`Unsupported purpose: ${request_context.purpose}`);
    }
  }

  if (errors.length > 0) {
    return res.status(400).json({
      status: 'error',
      error_code: 'INVALID_IDENTIFIER_INPUT',
      message: 'Request validation failed',
      errors,
    });
  }

  // Enforce request ownership: X-OneBox-Id header must match request_context.onebox_id
  if (req.caller && request_context?.onebox_id && req.caller.oneboxId !== request_context.onebox_id) {
    return res.status(403).json({
      status: 'error',
      error_code: 'ONEBOX_ID_MISMATCH',
      message: 'X-OneBox-Id header does not match request_context.onebox_id',
    });
  }

  next();
}

module.exports = { validateVerificationRequest };
