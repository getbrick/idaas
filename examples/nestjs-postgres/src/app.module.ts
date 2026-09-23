import "reflect-metadata";
import { Module } from "@nestjs/common";
import { GetbrickIdaasModule } from "@getbrick/idaas-nestjs";
import { auth } from "./auth.js";

@Module({
  imports: [GetbrickIdaasModule.forRoot({ auth })],
})
export class AppModule {}
