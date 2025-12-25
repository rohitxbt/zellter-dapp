const webpack = require('webpack');

module.exports = {
  webpack: function(config, env) {
    // --- CRITICAL FIX START ---
    // We must find the 'oneOf' array and insert our rule there.
    // Adding it to the top level config.module.rules DOES NOT WORK in CRA v5.
    const oneOfRule = config.module.rules.find((rule) => rule.oneOf);
    
    if (oneOfRule) {
      oneOfRule.oneOf.unshift({
        test: /\.m?js$/,
        resolve: {
          fullySpecified: false, // This forces Webpack to accept the Zama package import
        },
      });
    }
    // --- CRITICAL FIX END ---

    // Polyfills
    config.resolve.fallback = {
      ...config.resolve.fallback,
      "crypto": require.resolve("crypto-browserify"),
      "stream": require.resolve("stream-browserify"),
      "assert": require.resolve("assert"),
      "http": require.resolve("stream-http"),
      "https": require.resolve("https-browserify"),
      "os": require.resolve("os-browserify"),
      "url": require.resolve("url"),
      "vm": require.resolve("vm-browserify"),
      "process": require.resolve("process/browser"),
      "buffer": require.resolve("buffer/"),
    };

    // Extensions & Plugins
    config.resolve.extensions = ['.mjs', '.js', '.jsx', '.ts', '.tsx', '.json', ...config.resolve.extensions];
    
    config.plugins = (config.plugins || []).concat([
      new webpack.ProvidePlugin({
        process: 'process/browser',
        Buffer: ['buffer', 'Buffer']
      })
    ]);

    config.ignoreWarnings = [/Failed to parse source map/];

    return config;
  },

  devServer: function(configFunction) {
    return function(proxy, allowedHost) {
      const config = configFunction(proxy, allowedHost);
      config.headers = {
        ...config.headers,
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp"
      };
      return config;
    };
  },
};