import { defineWorkspace } from "vitest/config"

export default defineWorkspace([
    {
        test: {
            name: "node",
            environment: "node",
        },
    },
    {
        test: {
            name: "firefox",
            browser: {
                enabled: true,
                headless: true,
                name: "firefox",
                provider: "webdriverio",
                screenshotFailures: false,
            },
        },
    },
    {
        test: {
            name: "chrome",
            browser: {
                enabled: true,
                headless: true,
                name: "chrome",
                provider: "webdriverio",
                screenshotFailures: false,
            },
            globalSetup: "tests/setup.chrome.ts",
        },
    },
])
