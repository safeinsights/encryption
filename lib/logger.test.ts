import { afterEach, describe, expect, it, vi } from 'vitest'
import logger from './logger'

describe('logger', () => {
    afterEach(() => {
        vi.unstubAllEnvs()
    })

    it('always forwards warnings and errors to the console', () => {
        const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
        const error = vi.spyOn(console, 'error').mockImplementation(() => {})

        logger.warn('careful')
        logger.error('broken', 42)

        expect(warn).toHaveBeenCalledWith('encryption:warn careful')
        expect(error).toHaveBeenCalledWith('encryption:error broken', 42)
    })

    it('keeps debug and info quiet by default', () => {
        vi.stubEnv('NODE_ENV', 'test')
        vi.stubEnv('DEBUG', '')
        const log = vi.spyOn(console, 'log').mockImplementation(() => {})

        logger.debug('hidden')
        logger.info('hidden')

        expect(log).not.toHaveBeenCalled()
    })

    it('prints debug and info in development', () => {
        vi.stubEnv('NODE_ENV', 'development')
        const log = vi.spyOn(console, 'log').mockImplementation(() => {})

        logger.info('Adding file')

        expect(log).toHaveBeenCalledWith('encryption:info Adding file')
    })

    it('prints debug and info when DEBUG names encryption', () => {
        vi.stubEnv('NODE_ENV', 'test')
        vi.stubEnv('DEBUG', 'other,encryption:*')
        const log = vi.spyOn(console, 'log').mockImplementation(() => {})

        logger.debug('details')

        expect(log).toHaveBeenCalledWith('encryption:debug details')
    })
})
