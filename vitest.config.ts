import { defineConfig } from 'vitest/config'

// https://vitejs.dev/config/
export default defineConfig({
    test: {
        mockReset: true,
        environment: 'happy-dom',
        include: ['**/*.(test).{js,jsx,ts,tsx}'],
        coverage: {
            provider: 'v8',
            reporter: ['text', 'lcov'],
            all: true,
            include: ['job-results/**/*.ts', 'lib/**/*.ts', 'util/**/*.ts'],
        },
    },
})
