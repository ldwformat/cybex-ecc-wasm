const CopyWebpackPlugin = require("copy-webpack-plugin");
const CompressionPlugin = require("compression-webpack-plugin");

const path = require("path");

module.exports = {
  entry: "./bootstrap.js",
  output: {
    path: path.resolve(__dirname, "dist"),
    filename: "bootstrap.js"
  },
  mode: "development",
  // module: {
  //   rules: [
  //     {
  //       test: /.ts/,
  //       use: [
  //         {
  //           loader: "awesome-typescript-loader",
  //           options: {
  //             useBabel: true,
  //             useCache: true,
  //             useTranspileModule: true
  //           }
  //         }
  //       ],
  //       exclude: /node_modules/
  //     }
  //   ]
  // },
  // resolve: {
  //   extensions: [".tsx", ".ts", ".js"]
  // },
  plugins: [new CopyWebpackPlugin(["index.html"]), new CompressionPlugin()]
};
