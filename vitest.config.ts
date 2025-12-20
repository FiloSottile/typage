import { defineConfig } from "vitest/config"
import { webdriverio } from "@vitest/browser-webdriverio"

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
                        provider: webdriverio(),
                        screenshotFailures: false,
                    },
                },
            },
        ]
    }
})
