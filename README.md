# Basic-Mongoose-with-Express-Typescript

## initial command
1. npm init -y
2. npm i express
3. npm install mongoose --save
4. npm install typescript --save-dev
5. npm i cors dotenv
6. tsc --init
## middlewars typescript support setup 
1. npm i --save-dev @types/express
2. npm i --save-dev @types/cors

## eslint setup
1. add this two value in tsconfig.js
```
  "include": ["src"], // which files to compile
  "exclude": ["node_modules"], // which files to skip
```
2.npm install eslint @typescript-eslint/parser @typescript-eslint/eslint-plugin --save-dev
3. npx eslint --init

ques-1: How would you like to use ESLint?

ans-1 :To check syntax and find problems

ques-2:What type of modules does your project use?

ans-2 JavaScript modules (import/export)

ques-3: Which framework does your project use?

ans-3:none of these

ques-5: Where does your code run?

ans-5 : node

ques-6:What format do you want your config file to be in?

ans-6: JSON

4. create .eslintignore folder in root dir and add this two for gitignore
    1. node_modules
    2. dist

5. add this into package.json in scripts

```
"lint": "eslint --ignore-path .eslintignore --ext .js,.ts"
```


6. to fix auto 
```
// pakage.json
 "scripts": {
    // "build": "tsc",
    // "test": "echo \"Error: no test specified\" && exit 1",
    // "lint": "eslint src --ignore-path .eslintignore --ext .ts",
    "lint:fix":"npx eslint src --fix"
  },
```

7. add this into .eslintrc.json
   
   ```
     "rules": {
        "no-unused-vars": "error",
        "no-unused-expressions":"error",
        "prefer-const":"error",
        "no-console":"warn",
        "no-undef":"error"
    },
    "globals": {
        "process":"readonly"
    }
   ```

   ## Prettier setup

1. npm install --save-dev prettier
   
3. create .prettierrc.json file in root and add this
   
 ```
   
 {
  "semi": true,
  "singleQuote": true
}


```

3. add package.json in scripts

```

"format": "prettier --ignore-path .gitignore --write \"./src**/*.+(js|ts|json)\""

```

4. add two property in VSC-code setting.json

```

//vs code  settings.json
{
  "editor.defaultFormatter": "esbenp.prettier-vscode",
  "editor.formatOnSave": true,
  ...
}

```

5. Avoiding conflicts when working with ESLint and Prettier

```

npm install --save-dev eslint-config-prettier

```

6. go to .eslintrc file and replace extends with this

```

"extends": ["eslint:recommended", "plugin:@typescript-eslint/recommended", "prettier"],

```

7. add this into package.json in starts

```

"format:fix": "npx prettier --write src"

```


## Important Links

 - [Eslint And Prettier Setup](https://mobisoftinfotech.com/resources/blog/set-up-node-and-express-js-project-from-scratch-with-typescript-eslint-and-prettier)
 - [Eslint Doesnt Work In Vscode](https://stackoverflow.com/questions/75381505/what-is-the-reason-eslint-doesnt-work-in-vs-code)





