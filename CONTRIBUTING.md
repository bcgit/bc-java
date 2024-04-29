# Bouncy Castle Contributing Guidelines <!-- omit in toc -->

Thank you for contributing to Bouncy Castle!

In this guide, you get an overview of the contribution workflow from starting a discussion or opening an issue, to creating, reviewing, and merging a pull request.

For an overview of the project, see [README](README.md). 

### Start a discussion
If you have a question or problem, you can [search in discussions](https://github.com/bcgit/bc-java/discussions), if someone has already found a solution to your problem. 

Or you can [start a new discussion](https://github.com/bcgit/bc-java/discussions/new/choose) and ask your question. 

### Create an issue

If you find a problem with Bouncy Castle, [search if an issue already exists](https://github.com/bcgit/bc-java/issues).

> **_NOTE:_**  If the issue is a __potential security problem__, please contact us
before posting anything public. See [Security Policy](SECURITY.md).

If a related discussion or issue doesn't exist, and the issue is not security related, you can [open a new issue](https://github.com/bcgit/bc-java/issues/new). An issue can be converted into a discussion if regarded as one.

### Contribute to the code

For substantial, non-trivial contributions, you may be asked to sign a contributor assignment agreement. Optionally, you can also have your name and contact information listed in [Contributors](https://www.bouncycastle.org/contributors.html). 

Please note we are unable to accept contributions which cannot be released under the [Bouncy Castle License](https://www.bouncycastle.org/licence.html). Issuing a pull request on our public github mirror is taken as agreement to issuing under the Bouncy Castle License.

#### Create a pull request

> **_NOTE:_**  If the issue is a __potential security problem__, please contact us. See [Security Policy](SECURITY.md).

You are welcome to send patches, under the Bouncy Castle License, as pull requests. For more information, see [Creating a pull request](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/proposing-changes-to-your-work-with-pull-requests/creating-a-pull-request). For minor updates, you can instead choose to create an issue with short snippets of code. See above.

* For contributions touching multiple files try and split up the pull request, smaller changes are easier to review and test, as well as being less likely to run into merge issues.
* Create a test cases for your change, it may be a simple addition to an existing test. If you do not know how to do this, ask us and we will help you. 
* If you run into any merge issues, check out this [git tutorial](https://github.com/skills/resolve-merge-conflicts) to help you resolve merge conflicts and other issues.

For more information, refer to the Bouncy Castle documentation on [Getting Started with Bouncy Castle](https://doc.primekey.com/bouncycastle/introduction#Introduction-GettingStartedwithBouncyCastle).

#### Self-review

Don't forget to self-review. Please follow these simple guidelines:
* Keep the patch limited, only change the parts related to your patch. 
* Do not change other lines, such as whitespace, adding line breaks to Java doc, etc. It will make it very hard for us to review the patch.


#### Your pull request is merged

For acceptance, pull requests need to meet specific quality criteria, including tests for anything substantial. Someone on the Bouncy Castle core team will review the pull request when there is time, and let you know if something is missing or suggest improvements. If it is a useful and generic feature it will be integrated in Bouncy Castle to be available in a later release.

