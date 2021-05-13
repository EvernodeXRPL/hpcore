# Hot Pocket javascript client library and examples

Single-file javascript library to support json and bson protocols in NodeJs and Browser environments.

## NodeJs
1. Run `npm install` to install all the dependencies.
1. `lib/hp-client-lib.js` is the Hot Pocket client library for NodeJs.
1. `text-client.js` is the example for json mode.
1. `file-client.js` is the example for bson mode.

## Browser
1. Run `npm install` to install all the compilation dependencies.
1. Run `npm run build-browser` to produced the minified library for the browser.
1. `browser-example.html` is the simple html/javascript example for json mode.

(For BSON support in browser, a slightly modified version of https://www.npmjs.com/package/bson is used. The minified library includes this bson support library as well)