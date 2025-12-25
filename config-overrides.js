const webpack = require("webpack");

module.exports = {
  webpack: function (config, env) {

    // 🔥 RELAX EXPORT CONDITIONS (Zama SDK fix)
    config.resolve = config.resolve || {};
    config.resolve.conditionNames = [
      "browser",
      "import",
      "require",
      "default",
    ];

    // Browser polyfills
    config.resolve.fallback = {
      ...config.resolve.fallback,
      crypto: require.resolve("crypto-browserify"),
      stream: require.resolve("stream-browserify"),
      assert: require.resolve("assert"),
      http: require.resolve("stream-http"),
      https: require.resolve("https-browserify"),
      os: require.resolve("os-browserify"),
      url: require.resolve("url"),
      vm: require.resolve("vm-browserify"),
      process: require.resolve("process/browser"),
    };

    config.plugins = (config.plugins || []).concat([
      new webpack.ProvidePlugin({
        process: "process/browser",
        Buffer: ["buffer", "Buffer"],
      }),
    ]);

    // Allow imports outside src/
    config.resolve.plugins = config.resolve.plugins.filter(
      (plugin) =>
        !(
          plugin.constructor &&
          plugin.constructor.name === "ModuleScopePlugin"
        )
    );

    return config;
  },

  devServer: function (configFunction) {
    return function (proxy, allowedHost) {
      const config = configFunction(proxy, allowedHost);

      config.headers = {
        ...config.headers,
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Content-Security-Policy":
          "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' blob: https:; worker-src 'self' blob:; connect-src 'self' https: wss: blob:;",
      };

      return config;
    };
  },
};
