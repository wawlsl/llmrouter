# Documentation

PromptCache documentation is available at: **[https://messkan.github.io/prompt-cache](https://messkan.github.io/prompt-cache)**

## Local Development

To preview documentation locally:

```bash
# Install Jekyll (if not already installed)
gem install bundler jekyll

# Navigate to docs directory
cd docs

# Create Gemfile
cat > Gemfile << EOF
source 'https://rubygems.org'
gem 'github-pages', group: :jekyll_plugins
gem 'just-the-docs'
EOF

# Install dependencies
bundle install

# Serve locally
bundle exec jekyll serve

# Open browser to http://localhost:4000
```

## Documentation Structure

```
docs/
├── index.md              # Home page
├── getting-started.md    # Installation & quick start
├── api-reference.md      # REST API documentation
├── configuration.md      # Configuration guide
├── providers.md          # Provider setup & comparison
└── _config.yml          # Jekyll configuration
```

## Contributing to Documentation

1. Edit the relevant `.md` file in the `docs/` directory
2. Test locally with Jekyll
3. Submit a pull request

## Deployment

Documentation is automatically deployed to GitHub Pages when changes are pushed to the `main` branch via GitHub Actions (`.github/workflows/docs.yml`).

## Manual Deployment

If needed, you can deploy manually:

1. Go to your repository Settings → Pages
2. Set Source to "GitHub Actions"
3. Push to main branch to trigger deployment

## Theme

We use the [Just the Docs](https://just-the-docs.github.io/just-the-docs/) Jekyll theme for clean, searchable documentation.
