const webpack = require('webpack');

module.exports = {
  webpack: function(config, env) {
    // 1. Force handle .mjs and .js files with loose rules
    // We removed 'include: /node_modules/' to ensure this applies to ALL imports
    config.module.rules.push({
      test: /\.m?js/,
      resolve: {
        fullySpecified: false
      }
    });

    // 2. Add .mjs to the resolve extensions
    config.resolve.extensions = ['.mjs', '.js', '.jsx', '.ts', '.tsx', '.json', ...config.resolve.extensions];

    // 3. Polyfills for Node.js core modules (Required for Zama/Web3)
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
    
    // 4. Provide Global Variables
    config.plugins = (config.plugins || []).concat([
      new webpack.ProvidePlugin({
        process: 'process/browser',
        Buffer: ['buffer', 'Buffer']
      })
    ]);
    
    // 5. Ignore source map warnings that clutter logs
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