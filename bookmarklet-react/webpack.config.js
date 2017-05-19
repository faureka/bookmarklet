const path = require('path');
module.exports = {
  entry: './index.jsx',
  output: {
    filename: 'bundle.js'
  },
  module: {
    loaders: [{ 
        test: /\.jsx?$/,         // Match both .js and .jsx files
        exclude: /node_modules/, 
        loader: "babel-loader", 
        query:
        {
            presets:['react','es2015']
        }
    },
    ]
  }
}