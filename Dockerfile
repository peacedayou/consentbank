FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY src/ConsentBank/ConsentBank.csproj src/ConsentBank/
RUN dotnet restore src/ConsentBank/ConsentBank.csproj
COPY src/ src/
RUN dotnet publish src/ConsentBank/ConsentBank.csproj -c Release -o /app --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app .
RUN mkdir -p /data && chown app:app /data
USER app
ENV ASPNETCORE_URLS=http://+:8080 \
    ConnectionStrings__Default="Data Source=/data/consentbank.db"
EXPOSE 8080
ENTRYPOINT ["dotnet", "ConsentBank.dll"]
