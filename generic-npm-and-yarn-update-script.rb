# This script is designed to loop through all dependencies in a GHE, GitLab or
# Azure DevOps project, creating PRs where necessary.

require "dependabot/file_fetchers"
require "dependabot/file_parsers"
require "dependabot/update_checkers"
require "dependabot/file_updaters"
require "dependabot/pull_request_creator"
require "dependabot/rem_issue_creator"
require "dependabot/omnibus"
require_relative "vulnerability_fetcher"

credentials = [
  {
    "type" => "git_source",
    "host" => "github.com",
    "username" => "x-access-token",
    "password" => ENV["GITHUB_ACCESS_TOKEN"] # A GitHub access token with read access to public repos
  }
]

# Full name of the repo you want to create pull requests for.
repo_name = ENV["PROJECT_PATH"] # namespace/project
branch_name = ENV["PROJECT_BRANCH"] || nil # repo branch

# Directory where the base dependency files are.
directory = ENV["DIRECTORY_PATH"] || "/"

# Name of the package manager you'd like to do the update for. Options are:
# - bundler
# - pip (includes pipenv)
# - npm_and_yarn
# - maven
# - gradle
# - cargo
# - hex
# - composer
# - nuget
# - dep
# - go_modules
# - elm
# - submodules
# - docker
# - terraform
package_manager = ENV["PACKAGE_MANAGER"] || "npm_and_yarn"

# if ENV["GITHUB_ENTERPRISE_ACCESS_TOKEN"]
#   credentials << {
#     "type" => "git_source",
#     "host" => ENV["GITHUB_ENTERPRISE_HOSTNAME"], # E.g., "ghe.mydomain.com",
#     "username" => "x-access-token",
#     "password" => ENV["GITHUB_ENTERPRISE_ACCESS_TOKEN"] # A GHE access token with API permission
#   }

#   source = Dependabot::Source.new(
#     provider: "github",
#     hostname: ENV["GITHUB_ENTERPRISE_HOSTNAME"],
#     api_endpoint: "https://#{ENV['GITHUB_ENTERPRISE_HOSTNAME']}/api/v3/",
#     repo: repo_name,
#     directory: directory,
#     branch: branch_name,
#   )
# elsif ENV["GITLAB_ACCESS_TOKEN"]
#   gitlab_hostname = ENV["GITLAB_HOSTNAME"] || "gitlab.com"

#   credentials << {
#     "type" => "git_source",
#     "host" => gitlab_hostname,
#     "username" => "x-access-token",
#     "password" => ENV["GITLAB_ACCESS_TOKEN"] # A GitLab access token with API permission
#   }

#   source = Dependabot::Source.new(
#     provider: "gitlab",
#     hostname: gitlab_hostname,
#     api_endpoint: "https://#{gitlab_hostname}/api/v4",
#     repo: repo_name,
#     directory: directory,
#     branch: branch_name,
#   )
# elsif ENV["AZURE_ACCESS_TOKEN"]
#   azure_hostname = ENV["AZURE_HOSTNAME"] || "dev.azure.com"

#   credentials << {
#     "type" => "git_source",
#     "host" => azure_hostname,
#     "username" => "x-access-token",
#     "password" => ENV["AZURE_ACCESS_TOKEN"]
#   }

#   source = Dependabot::Source.new(
#     provider: "azure",
#     hostname: azure_hostname,
#     api_endpoint: "https://#{azure_hostname}/",
#     repo: repo_name,
#     directory: directory,
#     branch: branch_name,
#   )
# else
#   source = Dependabot::Source.new(
#     provider: "github",
#     repo: repo_name,
#     directory: directory,
#     branch: branch_name,
#   )
# end

source = Dependabot::Source.new(
  provider: "github",
  repo: repo_name,
  directory: directory,
  branch: branch_name,
)

##############################
# Fetch the dependency files #
##############################
puts "Fetching #{package_manager} dependency files for #{repo_name}"
fetcher = Dependabot::FileFetchers.for_package_manager(package_manager).new(
  source: source,
  credentials: credentials,
)

files = fetcher.files
commit = fetcher.commit

##############################
# Parse the dependency files #
##############################
puts "Parsing dependencies information"
parser = Dependabot::FileParsers.for_package_manager(package_manager).new(
  dependency_files: files,
  source: source,
  credentials: credentials,
)

dependencies = parser.parse

####################################################
# Get the security advisories for the dependencies #
####################################################
puts "Retrieving vulnerabilities information"
vulnerabilities = VulnerabilityFetcher.new(dependencies.map(&:name), package_manager, ENV["GITHUB_ACCESS_TOKEN"]).fetch_advisories

####################################################
# Create an Issue regard to the dependency metrics #
####################################################
lockfile = files.find{ |f| f.name == 'package-lock.json' }
package_json = files.find{ |f| f.name == 'package.json' }
if (not package_json.nil?) and (not lockfile.nil?)
  print "Creating Ripple-Effect of Metrics dependency graph on Issue"
  rem_issue_creator = Dependabot::RemIssueCreator.new(
    source: source,
    credentials: credentials,
    custom_labels: ['dependency graph', 'javascript', 'rem', 'npm search metrics'],
    lockfile: lockfile,
    package_json: package_json,
    metric: "final",
    rem_api: "http://helium.cs.uvic.ca/rem/rem-with-lockfile-for-issue"
  )
  rem_issue_creator.create
  puts " ..done"
end

dependencies.each do |dep|
  next if vulnerabilities[dep.name.to_sym].empty?

  ###########################################################
  # Build security advisory and Vulnerability Fixed message #
  ###########################################################
  version = Dependabot::Utils.version_class_for_package_manager(package_manager).new(dep.version)
  vulnerabilities_fixed = { dep.name => [] }
  security_advisories = []
  vulnerabilities[dep.name.to_sym].each do |vuln|
    vulnerable_versions = vuln[:vulnerable_versions].map { |v| Dependabot::Utils.requirement_class_for_package_manager(package_manager).new(v) }
    safe_versions = vuln[:patched_versions].map { |v| Dependabot::Utils.requirement_class_for_package_manager(package_manager).new(v) }
    security_advisory = Dependabot::SecurityAdvisory.new(
      dependency_name: dep.name,
      package_manager: package_manager,
      vulnerable_versions: vulnerable_versions,
      safe_versions: safe_versions
    )
    security_advisories.append(security_advisory)
    vulnerabilities_fixed[dep.name].append(
      {
        "title" => vuln[:severity] + " severity vulnerability",
        "description" => vuln[:summary] || "",
        "patched_versions" => vuln[:patched_versions] || [],
        "unaffected_versions" => [],
        "affected_versions" => vuln[:vulnerable_versions],
        "source_url" => vuln[:url] || "https://cve.mitre.org/",
        "source_name" => vuln[:cve_id] || "CVE security vulnerability database"
      }
    ) if security_advisory.vulnerable?(version)
  end

  #########################################
  # Get update details for the dependency #
  #########################################
  checker = Dependabot::UpdateCheckers.for_package_manager(package_manager).new(
    dependency: dep,
    dependency_files: files,
    credentials: credentials,
    security_advisories: security_advisories
  )

  next unless checker.vulnerable? # vulnerability update only
  next if checker.up_to_date?

  requirements_to_unlock =
    if !checker.requirements_unlocked_or_can_be?
      if checker.can_update?(requirements_to_unlock: :none) then :none
      else :update_not_possible
      end
    elsif checker.can_update?(requirements_to_unlock: :own) then :own
    elsif checker.can_update?(requirements_to_unlock: :all) then :all
    else :update_not_possible
    end

  next if requirements_to_unlock == :update_not_possible

  updated_deps = checker.updated_dependencies(
    requirements_to_unlock: requirements_to_unlock
  )

  #####################################
  # Generate updated dependency files #
  #####################################
  print "  - Updating #{dep.name} (from #{dep.version})…"
  updater = Dependabot::FileUpdaters.for_package_manager(package_manager).new(
    dependencies: updated_deps,
    dependency_files: files,
    credentials: credentials,
  )

  updated_files = updater.updated_dependency_files

  ########################################
  # Create a pull request for the update #
  ########################################
  pr_creator = Dependabot::PullRequestCreator.new(
    source: source,
    base_commit: commit,
    dependencies: updated_deps,
    files: updated_files,
    credentials: credentials,
    assignees: [(ENV["PULL_REQUESTS_ASSIGNEE"] || ENV["GITLAB_ASSIGNEE_ID"])&.to_i],
    label_language: true,
    rem_graph_files: {
      :package_json => package_json, 
      :lockfile => lockfile
    },
    rem_graph_api: "http://helium.cs.uvic.ca/rem/rem-vulnerable-with-lockfile",
    vulnerabilities_fixed: vulnerabilities_fixed,
  )
  pull_request = pr_creator.create
  puts " submitted"

  next unless pull_request

  # Enable GitLab "merge when pipeline succeeds" feature.
  # Merge requests created and successfully tested will be merge automatically.
  # if ENV["GITLAB_AUTO_MERGE"]
  #   g = Gitlab.client(
  #     endpoint: source.api_endpoint,
  #     private_token: ENV["GITLAB_ACCESS_TOKEN"]
  #   )
  #   g.accept_merge_request(
  #     source.repo,
  #     pull_request.iid,
  #     merge_when_pipeline_succeeds: true,
  #     should_remove_source_branch: true
  #   )
  # end
end

puts "Done"
