golang-kraftwerk-init-helper-cli
================================

Tool for products to create their certificates from `KRAFTWERK` manifests.

Certificate keys
----------------

``init`` defaults to EC P-256. Select RSA explicitly for products such as TAK
that also use this identity to sign RSA JWTs::

  kw_product_init init /pvarki/kraftwerk-init.json
  kw_product_init init --keytype RSA /pvarki/kraftwerk-init.json
  kw_product_init init --keytype EC --keybits 384 /pvarki/kraftwerk-init.json

``--keytype`` is case-insensitive. EC supports 256, 384 and 521 bits; RSA defaults
to 4096 bits and requires at least 2048. Existing ``--keybits`` callers requiring
RSA must now also specify ``--keytype RSA``. CSRs include the product DNS name
as a subject alternative name and request both client and server authentication.

``renew`` refreshes the CSR using the existing key and certificate CN, adding a
DNS SAN for older identities. It uses RMAPI's mTLS renewal endpoint and does not
reuse the single-use initialization JWT or change the key algorithm.

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

  docker build --ssh default --target devel_shell -t kraftwerk_init_helper:devel_shell .

.. code-block:: bash

  docker create --name kraftwerk_init_helper -v `pwd`":/app" -it `echo $DOCKER_SSHAGENT` kraftwerk_init_helper:devel_shell

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
