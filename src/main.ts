import * as core from "@actions/core";
import * as tc from "@actions/tool-cache";
import * as github from "@actions/github";
import { GitHub } from "@actions/github/lib/utils";
import * as crypto from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import semver from "semver";
import process from "node:process";
import { $ } from "execa";
import { createUnauthenticatedAuth } from "@octokit/auth-unauthenticated";
import axios, { isAxiosError } from "axios";

async function validateSubscription(): Promise<void> {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  let repoPrivate: boolean | undefined;

  if (eventPath && existsSync(eventPath)) {
    const eventData = JSON.parse(readFileSync(eventPath, "utf8"));
    repoPrivate = eventData?.repository?.private;
  }

  const upstream = "actions4gh/setup-gh";
  const action = process.env.GITHUB_ACTION_REPOSITORY;
  const docsUrl =
    "https://docs.stepsecurity.io/actions/stepsecurity-maintained-actions";

  core.info("")
  core.info("\u001b[1;36mStepSecurity Maintained Action\u001b[0m")
  core.info(`Secure drop-in replacement for ${upstream}`)
  if (repoPrivate === false)
    core.info("\u001b[32m\u2713 Free for public repositories\u001b[0m")
  core.info(`\u001b[36mLearn more:\u001b[0m ${docsUrl}`)
  core.info("")

  if (repoPrivate === false) return;

  const serverUrl = process.env.GITHUB_SERVER_URL || "https://github.com";
  const body: Record<string, string> = { action: action || "" };
  if (serverUrl !== "https://github.com") body.ghes_server = serverUrl;
  try {
    await axios.post(
      `https://agent.api.stepsecurity.io/v1/github/${process.env.GITHUB_REPOSITORY}/actions/maintained-actions-subscription`,
      body,
      { timeout: 3000 }
    );
  } catch (error) {
    if (isAxiosError(error) && error.response?.status === 403) {
      core.error(
          "\u001b[1;31mThis action requires a StepSecurity subscription for private repositories.\u001b[0m",
      );
      core.error(
          `\u001b[31mLearn how to enable a subscription: ${docsUrl}\u001b[0m`,
      );
      process.exit(1);
    }
    core.info("Timeout or API not reachable. Continuing to next step.");
  }
}

async function run(): Promise<void> {
  await validateSubscription();

  const cliToken = core.getInput("cli-token");
  const octokit = cliToken
    ? github.getOctokit(cliToken, { baseUrl: "https://api.github.com" })
    : new GitHub({
        baseUrl: "https://api.github.com",
        authStrategy: createUnauthenticatedAuth,
        auth: { reason: "no 'cli-token' input" },
      });
  let version = core.getInput("gh-version");
  if (version === "latest") {
    const { data } = await octokit.rest.repos.getLatestRelease({
      owner: "cli",
      repo: "cli",
    });
    version = data.tag_name.slice(1);
  } else {
    const releases = await octokit.paginate(octokit.rest.repos.listReleases, {
      owner: "cli",
      repo: "cli",
    });
    const versions: string[] = releases.map((release: { tag_name: string }) => release.tag_name.slice(1));
    const matched = semver.maxSatisfying(versions, version);
    if (!matched) {
      throw new Error(`No version matching '${version}' found`);
    }
    version = matched;
  }
  core.debug(`Resolved version: ${version}`);

  let found = tc.find("gh", version);
  core.setOutput("cache-hit", !!found);
  if (!found) {
    const platform = (
      {
        linux: "linux",
        darwin: "macOS",
        win32: "windows",
      } as Record<string, string>
    )[process.platform];
    const arch = (
      {
        x64: "amd64",
        arm: "arm",
        arm64: "arm64",
      } as Record<string, string>
    )[process.arch];
    const ext = (
      {
        linux: "tar.gz",
        darwin: semver.lt(version, "2.28.0") ? "tar.gz" : "zip",
        win32: "zip",
      } as Record<string, string>
    )[process.platform];
    const file = `gh_${version}_${platform}_${arch}.${ext}`;
    found = await tc.downloadTool(
      `https://github.com/cli/cli/releases/download/v${version}/${file}`
    );

    // Verify integrity using GitHub's release asset digest if available
    try {
      const { data: release } = await octokit.rest.repos.getReleaseByTag({
        owner: "cli",
        repo: "cli",
        tag: `v${version}`,
      });
      const asset = release.assets?.find((a: { name: string }) => a.name === file);
      const digest = (asset as unknown as { digest?: string })?.digest;
      if (digest) {
        const expectedHash = digest.replace("sha256:", "");
        const fileBuffer = readFileSync(found);
        const actualHash = crypto.createHash("sha256").update(fileBuffer).digest("hex");
        if (actualHash !== expectedHash) {
          throw new Error(`Integrity check failed for ${file}: expected ${expectedHash}, got ${actualHash}`);
        }
        core.info(`Integrity verified (SHA-256: ${expectedHash})`);
      } else {
        core.warning("No digest available for this release asset, skipping integrity check");
      }
    } catch (error) {
      if (error instanceof Error && error.message.startsWith("Integrity check failed")) {
        throw error;
      }
      core.warning("Could not verify integrity, continuing without verification");
    }

    if (file.endsWith(".zip")) {
      found = await tc.extractZip(found);
    } else {
      found = await tc.extractTar(found);
    }
    // The tarball/zip extracts to a subdirectory like gh_2.x.x_linux_amd64/ with bin/gh inside
    const extractedDir = `${found}/gh_${version}_${platform}_${arch}`;
    const binDir = existsSync(`${extractedDir}/bin`) ? `${extractedDir}/bin` : extractedDir;
    found = await tc.cacheDir(binDir, "gh", version);
  }
  core.addPath(found);
  core.setOutput("gh-version", version);

  const token = core.getInput("token");
  if (token) {
    const { hostname } = new URL(core.getInput("github-server-url"));
    await $({ input: token })`gh auth login --with-token --hostname ${hostname}`;
    core.setOutput("auth", true);
  } else {
    core.setOutput("auth", false);
  }
}

run().catch((error) => {
  core.setFailed(error instanceof Error ? error.message : String(error));
});
