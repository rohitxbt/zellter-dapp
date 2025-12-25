const webpack = require('webpack');

module.exports = {
  webpack: function(config, env) {
    // 1. [CRITICAL] Fix "'.' is not exported"
    // This makes your setup behave like Next.js by looking for
    // 'node' or 'default' versions of the package.
    config.resolve.conditionNames = [
      "import", 
      "require", 
      "node", 
      "default", 
      "browser"
    ];

    // 2. Fix .mjs files
    config.module.rules.push({
      test: /\.m?js$/,
      resolve: {
        fullySpecified: false,
      },
    });

    // 3. Standard Polyfills
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

    config.plugins = (config.plugins || []).concat([
      new webpack.ProvidePlugin({
        process: 'process/browser',
        Buffer: ['buffer', 'Buffer']
      })
    ]);

    // 4. Extensions
    config.resolve.extensions = ['.mjs', '.js', '.jsx', '.ts', '.tsx', '.json', ...config.resolve.extensions];

    return config;
  },
  
  // Keep devServer to fix header errors
  devServer: function(configFunction) {
    return function(proxy, allowedHost) {
      const config = configFunction(proxy, allowedHost);
      config.headers = {
        ...config.headers,
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Embedder-Policy": "require-corp",
      };
      return config;
    };
  },
};