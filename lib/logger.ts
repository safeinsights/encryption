import debug from 'debug'

const logger = {
    debug: debug('encryption:debug'),
    info: debug('encryption:info'),
    warn: debug('encryption:warn'),
    error: debug('encryption:error'),
}

// Enable debug output in development
if (process.env.NODE_ENV === 'development') {
    debug.enable('encryption:*')
}

// Forward warnings and errors to console
logger.warn.log = console.warn.bind(console)
logger.error.log = console.error.bind(console)

export default logger
