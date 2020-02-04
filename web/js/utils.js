/**
 * A pure function to pick specific keys from object, similar to https://lodash.com/docs/4.17.4#pick
 * Credtis: https://stackoverflow.com/questions/34658867/slice-specific-keys-in-javascript-object
 * @param {Object}obj: The object to pick the specified keys from
 * @param {Array}keys: A list of all keys to pick from obj
 */
const pick = (obj, keys) => 
  Object.keys(obj)
    .filter(i => keys.includes(i))
    .reduce((acc, key) => {
      acc[key] = obj[key];
      return acc;
    }, {})
