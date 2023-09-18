golang-kraftwerk-init-helper-cli
===============================

Tool for products to create their certificates from `KRAFTWERK` manifests.

Development
-----------

Prerequisites
*************

**Enable** `buildkit <https://docs.docker.com/develop/develop-images/build_enhancements/>`_

.. code-block:: bash

  export DOCKER_BUILDKIT=1

**Forward SSH-agent to running instance:**

**OSX:**

.. code-block:: bash

  export DOCKER_SSHAGENT="-v /run/host-services/ssh-auth.sock:/run/host-services/ssh-auth.sock -e SSH_AUTH_SOCK=/run/host-services/ssh-auth.sock"

**Linux:**

.. code-block:: bash

  export DOCKER_SSHAGENT="-v $SSH_AUTH_SOCK:$SSH_AUTH_SOCK -e SSH_AUTH_SOCK"

Create & start development container
************************************

Build the image, create a container and start the container

.. code-block:: bash

  docker build --ssh default --target dev_shell -t kraftwerk_init_helper:dev_shell .

.. code-block:: bash

  docker create --name kraftwerk_init_helper -v `pwd`":/app" -it `echo $DOCKER_SSHAGENT` kraftwerk_init_helper:dev_shell

.. code-block:: bash

  docker start -i kraftwerk_init_helper

pre-commit initialization
*************************

Once inside the container, run:

.. code-block:: bash

  pre-commit install && pre-commit run --all-files

That's it, now you have the development environment up & running.

Production
----------

Build the production image:

.. code-block:: bash

  docker build --ssh default --target production -t kraftwerk_init_helper:latest .

Run the image:

.. code-block:: bash

  docker run --rm -it --name kraftwerk_helper kraftwerk_init_helper:latest
