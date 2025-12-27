const webpack = require('webpack');
const path = require('path');

module.exports = {
  webpack: function(config, env) {
    // --- THE NUCLEAR FIX ---
    config.resolve.exportsFields = []; 
    // -----------------------

    // 1. Standard Polyfills
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

    // 2. Global Variables
    config.plugins = (config.plugins || []).concat([
      new webpack.ProvidePlugin({
        process: 'process/browser',
        Buffer: ['buffer', 'Buffer']
      })
    ]);

    // 3. Allow .mjs files
    config.module.rules.push({
      test: /\.m?js$/,
      resolve: {
        fullySpecified: false,
      },
    });

    // 4. Ignore Source Maps for node_modules
    config.module.rules.push({
      test: /\.js$/,
      enforce: "pre",
      use: ["source-map-loader"],
      exclude: /node_modules/,
    });
    config.ignoreWarnings = [/Failed to parse source map/];
    
    // 5. Extensions
    config.resolve.extensions = ['.mjs', '.js', '.jsx', '.ts', '.tsx', '.json', ...config.resolve.extensions];

    // 6. Fix for aliases (Nuclear fallout mitigation)
    config.resolve.alias = {
        ...config.resolve.alias,
        'x402/client': path.resolve(__dirname, 'node_modules/x402/dist/esm/client/index.mjs'),
        '@reown/appkit/core': path.resolve(__dirname, 'node_modules/@reown/appkit-core/dist/esm/exports/index.js'),
        '@reown/appkit-wallet/utils': path.resolve(__dirname, 'node_modules/@reown/appkit-wallet/dist/esm/exports/utils.js'),
        '@noble/curves/bls12-381': path.resolve(__dirname, 'node_modules/@noble/curves/esm/bls12-381.js'),
        '@noble/curves/ed25519': path.resolve(__dirname, 'node_modules/@noble/curves/esm/ed25519.js'),
        '@noble/curves/secp256k1': path.resolve(__dirname, 'node_modules/@noble/curves/esm/secp256k1.js'),
        '@noble/curves/bn254': path.resolve(__dirname, 'node_modules/@noble/curves/esm/bn254.js')
    };
    
    // 7. FIXED: Process specific node_modules (viem, ox, privy)
    // Updated with 'plugin-transform-class-static-block' to fix the SyntaxError
    config.module.rules.push({
        test: /\.(js|mjs|jsx|ts|tsx)$/,
        include: [
            path.resolve(__dirname, "node_modules/viem"),
            path.resolve(__dirname, "node_modules/ox"),
            path.resolve(__dirname, "node_modules/@privy-io"),
            path.resolve(__dirname, "node_modules/@walletconnect")
        ],
        loader: require.resolve('babel-loader'),
        options: {
            presets: [
                [require.resolve('babel-preset-react-app'), { runtime: 'automatic' }]
            ],
            // 👇 YEH LINE NAYI HAI - ISSE ERROR JAYEGA
            plugins: [
                require.resolve('@babel/plugin-transform-class-static-block')
            ]
        }
    });

    // 8. Fix for "Can't resolve .js extension" when it is actually .ts
    config.resolve.extensionAlias = {
        '.js': ['.ts', '.tsx', '.js', '.jsx'],
        '.mjs': ['.mts', '.mjs']
    };

    return config;
  },

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
