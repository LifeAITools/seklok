FROM oven/bun:1.2

WORKDIR /app

COPY package.json bunfig.toml ./
RUN bun install --frozen-lockfile || bun install

COPY tsconfig.json ./
COPY locales/ locales/
COPY src/ src/

RUN bun x tsc --noEmit

RUN mkdir -p /app/data

EXPOSE 4430

HEALTHCHECK --interval=30s --timeout=5s \
  CMD bun -e "fetch('http://localhost:4430/api/v1/status').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["bun", "run", "src/index.tsx"]
