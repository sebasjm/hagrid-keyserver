const path = require('path');
const html = require('html-webpack-plugin');
const text = require('extract-text-webpack-plugin');
const copy = require('copy-webpack-plugin')

module.exports = {
  mode: 'production',
  entry: './web/index.js',
  output: {
    filename: 'site.js',
    path: path.resolve(__dirname, 'dist', 'public', 'assets'),
    publicPath: '/assets'
  },
  module: {
    rules: [
      {
        test:/\.(s*)css$/,
        use: text.extract({
          fallback: 'style-loader',
          use: [
            'css-loader',
            'sass-loader',
            {
              loader: 'postcss-loader',
              options: {
                plugins: function () { // post css plugins, can be exported to postcss.config.js
                  return [
                    require('autoprefixer')
                  ];
                }
              }
            }
          ]
        })
      }
    ]
  },
  plugins: [
    new html({
      filename: '../../templates/layout.html.hbs',
      template: 'web/layout.html.hbs',
    }),
    new text({
      filename: 'site.css'
    }),
    new copy([
      {
        from: 'web/*.hbs',
        to: path.resolve(__dirname, 'dist', "templates"),
        ignore: [ 'layout.html.hbs' ],
        flatten: true
      }
    ])
  ]
};
