# Docker image for seahorn and Trusty OS

## Build 
To build, run the following command.

  ```
   docker build -t seahorn-verify-trusty -f seahorn-verify-trusty.Dockerfile .
  ```

This will take a while since it has to download, setup, and compile Trusty.

The build process will also generate a bitcode file for one verification task.

  
## Run

```
docker run --rm -it seahorn-verify-trusty
```

## Content
