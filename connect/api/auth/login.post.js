import { getUserByUsername } from '~/db/users';
import bcrypt from 'bcrypt';
import { generateTokens, sendRefreshToken } from '~/connect/utils/jwt';
import { userTransformer } from '~/connect/transfomers/users';
import { createRefreshToken } from '~/db/refreshTokens';
import { sendError } from 'h3';
export default defineEventHandler(async event => {
   const body = await useBody(event);

   const { username, password } = body;

   if (!username || !password) {
      return sendError(
         event,
         createError({
            statusCode: 400,
            statusMessage: 'Invalid params',
         }),
      );
   }

   const user = await getUserByUsername(username);

   if (!user) {
      return sendError(
         event,
         createError({
            statusCode: 400,
            statusMessage: 'Username or Password is Invalid',
         }),
      );
   }

   const doesThePasswordMatch = await bcrypt.compare(password, user.password);

   if (!doesThePasswordMatch) {
      return sendError(
         event,
         createError({
            statusCode: 400,
            statusMessage: 'Username or Password is Invalid',
         }),
      );
   }

   //Access Token
   //Refresh Token

   const { accessToken, refreshToken } = generateTokens(user);

   await createRefreshToken({
      token: refreshToken,
      userId: user.id,
   });

   sendRefreshToken(event, refreshToken);

   return {
      accessToken: accessToken,
      user: userTransformer(user),
   };
});
