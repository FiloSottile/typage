import { defineConfig } from "vitest/config"

export default defineConfig({
    test: {
        projects: [
            {
                test: {
                    name: "node",
                },
            },
            {
                test: {
                    name: "browser",
                    browser: {
                        enabled: true,
                        headless: true,
                        instances: [{
                            browser: "firefox",
                        }, {
                            browser: "chrome",
                        }],
                        provider: "webdriverio",
                        screenshotFailures: false,
                    },
                },
            },
        ]
    }
})
