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

# re nodes that will be used in issues-rem
issues_re_nodes = []
dependencies.each do |dep|
  next if vulnerabilities[dep.name.to_sym].empty?

  ###########################################################
  # Build security advisory and Vulnerability Fixed message #
  ###########################################################
  version = Dependabot::Utils.version_class_for_package_manager(package_manager).new(dep.version)
  vulnerabilities[dep.name.to_sym].each do |vuln|
    vulnerable_versions = vuln[:vulnerable_versions].map { |v| Dependabot::Utils.requirement_class_for_package_manager(package_manager).new(v) }
    safe_versions = vuln[:patched_versions].map { |v| Dependabot::Utils.requirement_class_for_package_manager(package_manager).new(v) }
    security_advisory = Dependabot::SecurityAdvisory.new(
      dependency_name: dep.name,
      package_manager: package_manager,
      vulnerable_versions: vulnerable_versions,
      safe_versions: safe_versions
    )
    issues_re_nodes.append([dep.name,dep.version]) if security_advisory.vulnerable?(version)
  end  
end

####################################################
# Create an Issue regard to the dependency metrics #
####################################################
issues_re_nodes = issues_re_nodes.uniq
lockfile = files.find{ |f| f.name == 'package-lock.json' }
package_json = files.find{ |f| f.name == 'package.json' }
if (not package_json.nil?) and (not lockfile.nil?)
  print "Creating Ripple-Effect of Metrics dependency graphs on Issue"
  rem_issue_creator = Dependabot::RemIssueCreator.new(
    source: source,
    credentials: credentials,
    custom_labels: ['dependency graph', 'javascript', 'rem', 'npm search metrics', 'cve'],
    lockfile: lockfile,
    package_json: package_json,
    metric: nil,
    re_nodes: issues_re_nodes,
    rem_api: "http://helium.cs.uvic.ca/rem/rem-with-lockfile-for-issues-v2",
    commit: commit
  )
  rem_issue_creator.create
  puts " ..done"
end

puts "Done"
