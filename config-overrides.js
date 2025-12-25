webpack: function(config, env) {

  // 🔥 ADD THIS (safe)
  config.resolve = config.resolve || {};
  config.resolve.conditionNames = [
    "browser",
    "import",
    "require",
    "default"
  ];

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
  };

  config.plugins = (config.plugins || []).concat([
    new webpack.ProvidePlugin({
      process: 'process/browser',
      Buffer: ['buffer', 'Buffer']
    })
  ]);

  config.resolve.plugins = config.resolve.plugins.filter(plugin =>
    !(plugin.constructor && plugin.constructor.name === "ModuleScopePlugin")
  );

  return config;
},
