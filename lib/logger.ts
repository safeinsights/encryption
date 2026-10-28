// No `debug` package: it is CommonJS, and its require('tty') crashes consumers that bundle this
// library as ESM (the management-app migrator Lambda).
type LogFn = (message: string, ...args: unknown[]) => void

// Checked on each call so tests and long-lived processes see env changes.
function isVerbose(): boolean {
    if (typeof process === 'undefined') return false
    return process.env.NODE_ENV === 'development' || Boolean(process.env.DEBUG?.includes('encryption'))
}

const verbose =
    (level: string): LogFn =>
    (message, ...args) => {
        // eslint-disable-next-line no-console -- this module is the console wrapper
        if (isVerbose()) console.log(`encryption:${level} ${message}`, ...args)
    }

const logger: Record<'debug' | 'info' | 'warn' | 'error', LogFn> = {
    debug: verbose('debug'),
    info: verbose('info'),
    warn: (message, ...args) => console.warn(`encryption:warn ${message}`, ...args),
    error: (message, ...args) => console.error(`encryption:error ${message}`, ...args),
}

export default logger
